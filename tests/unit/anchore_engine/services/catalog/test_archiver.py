import json
import os
import time

import pytest

from anchore_engine.db.entities.catalog import (
    ArchivedImage,
    ArchivedImageDocker,
    ArchiveTransitions,
    CatalogImage,
    CatalogImageDocker,
)
from anchore_engine.services.catalog import archiver
from anchore_engine.utils import ensure_bytes


def test_archive_basic():
    path = "testarc.tar.gz"
    with archiver.ImageArchive(path, mode="w") as arc:
        arc.image_digest = "sha256:1234567890abcdef"
        arc.account = "testaccount"
        arc.add_artifact(
            "analysis",
            archiver.ObjectStoreLocation(bucket="somebucket", key="somekey"),
            data=ensure_bytes(json.dumps({"somedata": "somekey"})),
            metadata={"size": 0},
        )

    with archiver.ImageArchive(path, mode="r") as arc:
        print(arc.manifest.artifacts)
        assert len(arc.manifest.artifacts) == 1
        s = arc.extract_artifact("analysis")
        print(s)
        assert s == ensure_bytes(json.dumps({"somedata": "somekey"}))

    os.remove(path)


def test_archive_notfound():
    """
    Neg test archive
    :return:
    """
    try:
        with archiver.ImageArchive.for_reading("notrealfile") as arc:
            pytest.fail("Should have thrown exception")

    except IOError as ex:
        print("Correctly got exception: {}".format(ex))

    try:
        with archiver.ImageArchive.for_reading("somefile") as arc:
            pytest.fail("Should have thrown exception")

    except IOError as ex:
        print("Correctly got exception: {}".format(ex))


def _build_tag_history(
    registry, repository, tag, depth, account, time_interval_sec=86400
):
    history = []

    for i in range(depth):
        digest = "sha256:{}".format(i)
        # Generate from newest to oldest
        t = CatalogImageDocker()
        t.userId = account
        t.created_at = int(time.time()) - (i * time_interval_sec)
        t.last_updated = t.created_at
        t.tag_detected_at = t.created_at
        t.registry = registry
        t.repo = repository
        t.tag = tag
        t.imageDigest = digest
        t.digest = t.imageDigest
        t.record_state_key = "active"
        t.record_state_val = "true"

        img = CatalogImage()
        img.imageDigest = digest
        img.created_at = t.created_at
        img.last_updated = img.created_at + 10
        img.analysis_status = "analyzed"
        img.image_status = "active"
        img.userId = account
        img.analyzed_at = img.last_updated

        history.append((t, img))

    return history


def _build_archived_tag_history(
    registry, repository, tag, depth, account, time_interval_sec=86400
):
    history = []

    for i in range(depth):
        digest = "sha256:{}".format(i)
        # Generate from newest to oldest
        t = ArchivedImageDocker()
        t.account = account
        t.imageDigest = digest
        t.created_at = int(time.time()) - (i * time_interval_sec)
        t.last_updated = t.created_at
        t.tag_detected_at = t.created_at
        t.registry = registry
        t.repository = repository
        t.tag = tag

        img = ArchivedImage()
        img.imageDigest = digest
        img.created_at = t.created_at
        img.last_updated = img.created_at + 10
        img.account = account
        img.manifest_key = img.imageDigest
        img.manifest_bucket = "somebucket"
        img.archive_size_bytes = 10000
        img.status = "archived"
        img.analyzed_at = img.last_updated
        img._tags = [t]

        history.append((t, img))

    return history


def test_transitions_selector():
    account = "admin"
    task = archiver.ImageAnalysisArchiver("task1", "admin")

    def data_generator():
        tag1_hist = _build_tag_history(
            "docker.io", "sometest/somerepo", "latest", 5, account
        )
        tag2_hist = _build_tag_history(
            "docker.io", "sometest/somerepo", "alpine", 5, account
        )
        tag3_hist = _build_tag_history(
            "docker.io", "sometest/someotherrepo", "latest", 5, account
        )

        results = tag1_hist + tag2_hist + tag3_hist

        print("Raw history: {}".format("\n".join([str(x) for x in results])))

        for r in results:
            yield r

    rule = archiver.ArchiveTransitionRule()
    rule.account = account
    rule.tag_versions_newer = 3
    rule.selector_tag = None
    rule.selector_repository = None
    rule.selector_registry = None
    result = task._evaluate_tag_history_and_exclude(rule, data_generator())

    print("Transitions found: {} results".format(result))


def test_rule_match_merger():
    """
    Test the merging function
    :return:
    """

    count = 3
    depth = 2
    tags = {}
    images = {}

    for i in range(count):
        for (tag, img) in _build_tag_history(
            "docker.io",
            "testregistr-{}".format(i),
            str(i),
            depth=depth,
            account="admin",
        ):
            if img.imageDigest not in tags:
                tags[img.imageDigest] = [tag]
            else:
                tags[img.imageDigest].append(tag)
            images[img.imageDigest] = img

    def image_tag_lookup_callback(account, digest):
        return tags.get(digest)

    merger = archiver.ArchiveTransitionTask.TagRuleMatchMerger(
        "task1", "admin", image_tag_lookup_callback
    )

    rule = archiver.ArchiveTransitionRule()
    rule.account = "admin"
    rule.selector_repository = "library/node"
    rule.selector_registry = "*"
    rule.selector_tag = "*"
    rule.analysis_age_days = 1
    rule.transition = ArchiveTransitions.archive

    rule2 = archiver.ArchiveTransitionRule()
    rule2.account = "admin"
    rule2.selector_repository = "myinternal/nodejs"
    rule2.selector_registry = "*"
    rule2.selector_tag = "*"
    rule2.analysis_age_days = 1
    rule2.transition = ArchiveTransitions.archive

    print("Data: images={}, tags={}".format(images, tags))

    merger.add_rule_result(rule, [(tags["sha256:0"][0], images["sha256:0"])])
    merger.add_rule_result(rule2, [(t, images["sha256:1"]) for t in tags["sha256:1"]])

    result = merger.full_matched_digests()
    print("Merged result = {}".format(result))
    assert set(result) == {"sha256:1"}

    print("Evalauting split matches")
    merger = archiver.ArchiveTransitionTask.TagRuleMatchMerger(
        "task2", "admin", image_tag_lookup_callback
    )
    merger.add_rule_result(
        rule, [(t, images["sha256:0"]) for t in tags["sha256:0"][:1]]
    )
    merger.add_rule_result(
        rule2, [(t, images["sha256:0"]) for t in tags["sha256:0"][1:]]
    )
    merger.add_rule_result(rule2, [(t, images["sha256:1"]) for t in tags["sha256:1"]])

    result = merger.full_matched_digests()
    print("Merged result = {}".format(result))
    assert set(result) == {"sha256:0", "sha256:1"}

    # Check ordering
    print("Evaluating different orders of tag")
    merger = archiver.ArchiveTransitionTask.TagRuleMatchMerger(
        "task3", "admin", image_tag_lookup_callback
    )
    merger.add_rule_result(rule, [(t, images["sha256:0"]) for t in tags["sha256:0"]])
    merger.add_rule_result(rule2, [(t, images["sha256:1"]) for t in tags["sha256:1"]])

    result = merger.full_matched_digests()
    print("Merged result = {}".format(result))
    assert set(result) == {"sha256:1", "sha256:0"}


def test_rule_match_merge_large():
    """
    Test the merging function
    :return:
    """
    count = 1000
    depth = 10
    tags = {}
    images = {}

    for i in range(count):
        for (tag, img) in _build_tag_history(
            "docker.io", "testregistry", str(i), depth=depth, account="admin"
        ):
            if img.imageDigest not in tags:
                tags[img.imageDigest] = [tag]
            else:
                tags[img.imageDigest].append(tag)
            images[img.imageDigest] = img

    def image_tag_lookup_callback(account, digest):
        return tags.get(digest)

    merger = archiver.ArchiveTransitionTask.TagRuleMatchMerger(
        "task1", "admin", image_tag_lookup_callback
    )

    rule = archiver.ArchiveTransitionRule()
    rule.account = "admin"
    rule.selector_repository = "library/node"
    rule.selector_registry = "*"
    rule.selector_tag = "*"
    rule.analysis_age_days = 1
    rule.transition = ArchiveTransitions.archive

    merger.add_rule_result(rule, [(t, images["sha256:1"]) for t in tags["sha256:1"]])

    result = merger.full_matched_digests()
    print("Merged result = {}".format(result))
    if merger.image_tags_subset_matched:
        print(
            set(merger.image_tags["sha256:1"]).symmetric_difference(
                merger.image_tags_subset_matched["sha256:1"]
            )
        )
    assert set(result) == {"sha256:1"}

    for i in range(depth):
        merger.add_rule_result(
            rule,
            [(t, images["sha256:{}".format(i)]) for t in tags["sha256:{}".format(i)]],
        )

    result = merger.full_matched_digests()
    print("Merged result = {}".format(result))
    assert set(result) == {"sha256:{}".format(x) for x in range(depth)}


def test_delete_rule_match_merge():
    """
    Test the merging function for 'delete' operations, which use the archived records instead of catalog records

    :return:
    """
    count = 5
    depth = 3
    tags = {}
    images = {}

    for i in range(count):
        for (tag, img) in _build_archived_tag_history(
            "docker.io", "testregistry", str(i), depth=depth, account="admin"
        ):
            if img.imageDigest not in tags:
                tags[img.imageDigest] = [tag]
            else:
                tags[img.imageDigest].append(tag)
            images[img.imageDigest] = img

    def image_tag_lookup_callback(account, digest):
        return tags.get(digest)

    merger = archiver.ArchiveTransitionTask.TagRuleMatchMerger(
        "task1", "admin", image_tag_lookup_callback
    )

    rule = archiver.ArchiveTransitionRule()
    rule.account = "admin"
    rule.selector_repository = "testregistry"
    rule.selector_registry = "*"
    rule.selector_tag = "*"
    rule.analysis_age_days = 1
    rule.transition = ArchiveTransitions.delete

    merger.add_rule_result(rule, [(t, images["sha256:1"]) for t in tags["sha256:1"]])

    result = merger.full_matched_digests()
    print("Merged result = {}".format(result))
    if merger.image_tags_subset_matched:
        print(
            set(merger.image_tags["sha256:1"]).symmetric_difference(
                merger.image_tags_subset_matched["sha256:1"]
            )
        )
    assert set(result) == {"sha256:1"}

    for i in range(depth):
        merger.add_rule_result(
            rule,
            [(t, images["sha256:{}".format(i)]) for t in tags["sha256:{}".format(i)]],
        )

    result = merger.full_matched_digests()
    print("Merged result = {}".format(result))
    assert set(result) == {"sha256:{}".format(x) for x in range(depth)}
