from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger


class SuidModeDiffTrigger(BaseTrigger):
    __trigger_name__ = 'suidmodediff'
    __description__ = 'triggers if file is suid, but mode is different between the image and its base'

    def evaluate(self, image_obj, context):
        added = context.data.get('added_suid_files', {})
        for path, mode in added.items():
            self._fire(instance_id=path + '-' + self.__trigger_name__,
                       msg="SUID file mode in container is different from baseline for file - " + path)


class SuidFileAddTrigger(BaseTrigger):
    __trigger_name__ = 'suidfileadd'
    __description__ = 'triggers if the evaluated image has a file that is SUID and the base image does not'

    def evaluate(self, image_obj, context):
        added = context.data.get('added_suid_files', {})
        for path, mode in added.items():
            self._fire(instance_id=path + '-' + self.__trigger_name__, msg="SUID file has been added to image since base - " + path)


class SuidFileDelTrigger(BaseTrigger):
    __trigger_name__ = 'suidfiledel'
    __description__ = 'triggers if the base image has a SUID file, but the evaluated image does not'

    def evaluate(self, image_obj, context):
        removed = context.data.get('removed_suid_files', {})

        for path, mode in removed.items():
            self._fire(instance_id=path + '-' + self.__trigger_name__, msg="SUID file has been removed from image since base - " + path)


class SuidDiffTrigger(BaseTrigger):
    __trigger_name__ = 'suiddiff'
    __description__ = 'triggers if any one of the other events for this gate have triggered'

    def evaluate(self, image_obj, context):
        added = context.data.get('added_suid_files')
        removed = context.data.get('removed_suid_files')
        changed = context.data.get('changed_suid_files')

        if added or removed or changed:
            self._fire(msg='SUIDDIFF SUID file manifest is different from image to base')


class SuidDiffGate(Gate):
    __gate_name__ = 'suiddiff'
    __description__ = 'SetUID File Checks'
    __triggers__ = [
        SuidDiffTrigger,
        SuidFileAddTrigger,
        SuidFileDelTrigger,
        SuidModeDiffTrigger
    ]

    def prepare_context(self, image_obj, context):
        """
        Prepare the context by loading the base image and the suid entries for each
        :param image_obj:
        :param context:
        :return:
        """

        base_img = image_obj.get_image_base()
        if not base_img or base_img.id == image_obj.id:
            return context # No diffs to compute

        img_files = image_obj.fs.files
        img_suid_files = {k: v for k, v in filter(lambda x: x[1], { path: meta.get('suid') for path, meta in img_files.items()}.items())}

        base_files = base_img.fs.files
        base_suid_files = {k: v for k, v in filter(lambda x: x[1], { path: meta.get('suid') for path, meta in base_files.items()}.items())}

        added_keys = set(img_suid_files.keys()).difference(set(base_suid_files.keys()))
        removed_keys = set(base_suid_files.keys()).difference(set(img_suid_files.keys()))
        common_keys = set(base_suid_files.keys()).intersection(set(img_suid_files.keys()))

        added = {k: v for k, v in filter(lambda x: x[0] in added_keys, img_suid_files.items())}
        removed = {k: v for k, v in filter(lambda x: x[0] in removed_keys, base_suid_files.items())}
        changed = {k: v for k, v in filter(lambda x: x[0] in common_keys and img_suid_files[x[0]] != base_suid_files[x[0]], img_suid_files.items())}

        context.data['added_suid_files'] = added
        context.data['base_suid_files'] = removed
        context.data['changed_suid_files'] = changed
        return context
