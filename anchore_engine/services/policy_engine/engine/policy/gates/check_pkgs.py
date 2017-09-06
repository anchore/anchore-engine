from anchore_engine.services.policy_engine.engine.util.users import user_ids_to_search
from anchore_engine.db import Image
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger


class PkgDiffTrigger(BaseTrigger):
    __trigger_name__ = 'PKGDIFF'
    __description__ = 'triggers if any one of the other events has triggered'

    def evaluate(self, image_obj, context):
        if context.data.get('pkgs_added') or context.data.get('pkgs_removed') or context.data.get('pkgs_changed'):
            self._fire(msg="PKGDIFF Package manifest is different from image to base")


class PkgVersionDiffTrigger(BaseTrigger):
    __trigger_name__ = 'PKGVERSIONDIFF'
    __description__ = 'triggers if the evaluated image has a package installed with a different version of the same package from a previous base image'

    def evaluate(self, image_obj, context):
        changes = context.data.get('pkgs_changed', {})

        for name, version in changes:
            self._fire(instance_id=name + '-' + self.__trigger_name__,
                       msg="Package version in container is different from baseline for pkg - " + name)


class PkgAddTrigger(BaseTrigger):
    __trigger_name__ = 'PKGADD'
    __description__ = 'triggers if image contains a package that is not in its base'

    def evaluate(self, image_obj, context):
        added = context.data.get('pkgs_added', {})

        for name, version in added.items():
            self._fire(instance_id=name + '-' + self.__trigger_name__,
                       msg="Package has been added to image since base - " + name)


class PkgDelTrigger(BaseTrigger):
    __trigger_name__ = 'PKGDEL'
    __description__ = 'triggers if image has removed a package that is installed in its base'

    def evaluate(self, image_obj, context):
        removed = context.data.get('pkgs_removed', {})

        for name, version in removed:
            self._fire(instance_id=name + '-' + self.__trigger_name__,
                       msg="Package has been removed to image since base - " + name)


class PkgDiffGate(Gate):
    __gate_name__ = 'PKGDIFF'
    __triggers__ = [
        PkgVersionDiffTrigger,
        PkgAddTrigger,
        PkgDelTrigger,
        PkgDiffTrigger
    ]

    def prepare_context(self, image_obj, context):
        """
        Prepare the context by loading the base image for the given image. Performs a package diff operation
        and presents it in the context for use by triggers a few data keys:
        base_img -> Image object of the base image for the given image
        pkgs_added -> {<pkg_name>:<version>} for packages added to base in newer image
        pkgs_removed -> {<pkg_name>:<version>} for packages removed from the base by newer image
        pkgs_changed => {<pkg_name>:(<base_version>, <new_version>)} for packages with version diffs between base and new img

        :param image_obj:
        :param context: initial execution context
        :return: prepared ExecutionContext for use by triggers
        """

        # This is purely an optimization. Each trigger could do this to evaluate their condition check individually, but
        # doing it here is much more efficient.

        base_id = image_obj.familytree_json[0]
        if base_id != image_obj.id:
            base_img = context.db.query(Image).get((base_id, image_obj.user_id))
            context.data['base_img'] = base_img
        else:
            context.data['base_img'] = image_obj
            return context

        img_pkgs = {pkg.name: pkg.fullversion for pkg in image_obj.packages} if image_obj else {}
        base_pkgs = {pkg.name: pkg.fullversion for pkg in base_img.packages} if base_img else {}

        added_names = set(img_pkgs.keys()).difference(set(base_pkgs.keys()))
        removed_names = set(base_pkgs.keys()).difference(set(img_pkgs.keys()))
        intersection_names = set(img_pkgs.keys()).intersection(set(base_pkgs.keys()))

        context.data['pkgs_added'] = {name: img_pkgs[name] for name in added_names}
        context.data['pkgs_removed'] = {name: base_pkgs[name] for name in removed_names}
        context.data['pkgs_changed'] = {name: (base_pkgs[name], img_pkgs[name]) for name in
                                        filter(lambda x: img_pkgs[x] != base_pkgs[x], intersection_names)}

        return context
