import random

from anchore_engine.services.catalog import _perform_queue_rebalance

queue_rebalance_template = {
    "fooacct0": {},
    "fooacct1": {},
    "fooacct2": {},
    "fooacct3": {},
    "fooacct4": {},
    "fooacct5": {},
    "fooacct6": {},
    "fooacct7": {},
    "fooacct8": {},
    "fooacct9": {},
    "fooacct10": {},
}
highest_neg_queueId_base = -1 * (1024 * 1000)


def test_queue_rebalancer_empty():
    # no work in the queue
    queue_rebalance_input = queue_rebalance_template
    highest_neg_queueId_input = highest_neg_queueId_base
    computed_queue_id_updates = _perform_queue_rebalance(
        queue_rebalance_input, highest_neg_queueId_input
    )
    computed_queue_id_updates.sort()
    expected_queue_id_updates = []
    expected_queue_id_updates.sort()

    computed_test = computed_queue_id_updates
    expected_test = expected_queue_id_updates

    if computed_test != expected_test:
        print(
            "INPUTS: highest_neg_queueId={} queue_rebalance={}".format(
                highest_neg_queueId_input, queue_rebalance_input
            )
        )
        print("COMPUTED QUEUE UPDATES: {}".format(computed_test))
        print("EXPECTED QUEUE UPDATES: {}".format(expected_test))
    assert computed_test == expected_test


def test_queue_rebalancer_spikeload_initial():
    # when there is a spike of load and all accts have lowest queue Ids in the pos space, the tasks will not be balanced.  Ensure all are rebalanced into the neg space
    queue_rebalance_input = queue_rebalance_template
    for i in range(0, 10):
        queue_rebalance_input["fooacct{}".format(i)]["lowest_queueId"] = random.randint(
            1, 10000000000
        )
    highest_neg_queueId_input = highest_neg_queueId_base
    computed_queue_id_updates = _perform_queue_rebalance(
        queue_rebalance_input, highest_neg_queueId_input
    )

    computed_test = []
    for t, c in computed_queue_id_updates:
        computed_test.append(c)
    computed_test.sort()

    expected_test = []
    for i in range(0, 10):
        expected_test.append(highest_neg_queueId_base + (i + 1))

    if computed_test != expected_test:
        print(
            "INPUTS: highest_neg_queueId={} queue_rebalance={}".format(
                highest_neg_queueId_input, queue_rebalance_input
            )
        )
        print("COMPUTED QUEUE UPDATES: {}".format(computed_test))
        print("EXPECTED QUEUE UPDATES: {}".format(expected_test))
    assert computed_test == expected_test


def test_queue_rebalancer_spikeload_midway():
    # when some accts have pos lowest queueIds, and others already have neg queueIds, the pos ones need to get scheduled *behind* the existing neg ones
    queue_rebalance_input = queue_rebalance_template
    for i in range(0, 5):
        highest_neg_queueId_input = highest_neg_queueId_base + (i + 1)
        queue_rebalance_input["fooacct{}".format(i)][
            "lowest_queueId"
        ] = highest_neg_queueId_input

    for i in range(5, 10):
        queue_rebalance_input["fooacct{}".format(i)]["lowest_queueId"] = random.randint(
            1, 10000000000
        )

    computed_queue_id_updates = _perform_queue_rebalance(
        queue_rebalance_input, highest_neg_queueId_input
    )

    computed_test = []
    for t, c in computed_queue_id_updates:
        computed_test.append(c)
    computed_test.sort()

    expected_test = []
    for i in range(0, 5):
        expected_test.append(highest_neg_queueId_base + 5 + (i + 1))

    if computed_test != expected_test:
        print(
            "INPUTS: highest_neg_queueId={} queue_rebalance={}".format(
                highest_neg_queueId_input, queue_rebalance_input
            )
        )
        print("COMPUTED QUEUE UPDATES: {}".format(computed_test))
        print("EXPECTED QUEUE UPDATES: {}".format(expected_test))
    assert computed_test == expected_test


def test_queue_rebalancer_spikeload_inflight():
    # no rebalancing is performed if all accts already have a queue Id in the neg space
    queue_rebalance_input = queue_rebalance_template
    for i in range(0, 10):
        highest_neg_queueId_input = highest_neg_queueId_base + (i + 1)
        queue_rebalance_input["fooacct{}".format(i)][
            "lowest_queueId"
        ] = highest_neg_queueId_input

    computed_queue_id_updates = _perform_queue_rebalance(
        queue_rebalance_input, highest_neg_queueId_input
    )

    computed_test = []
    for t, c in computed_queue_id_updates:
        computed_test.append(c)
    computed_test.sort()

    expected_test = []

    if computed_test != expected_test:
        print(
            "INPUTS: highest_neg_queueId={} queue_rebalance={}".format(
                highest_neg_queueId_input, queue_rebalance_input
            )
        )
        print("COMPUTED QUEUE UPDATES: {}".format(computed_test))
        print("EXPECTED QUEUE UPDATES: {}".format(expected_test))
    assert computed_test == expected_test
