# import json
#
# from anchore_engine.subsys import logger
# from anchore_engine.db import db_archivedocument
# from anchore_engine import db
#
#
# class DataMigrationManager(object):
#     """
#     Migrates archive data from one driver impl to another.
#
#     """
#
#     def __init__(self, from_driver, to_driver):
#         self.source = from_driver
#         self.dest = to_driver
#
#     def start(self):
#         pass
#
#     def cancel(self):
#         pass
#
#     def state(self):
#         pass
#
#
# class Legacy(object):
#     @staticmethod
#     def do_archive_convert(localconfig, from_driver, to_driver):
#         myconfig = localconfig['services']['catalog']
#         if from_driver == 'db' and to_driver == 'localfs':
#             return(Legacy._converter_db_to_localfs(myconfig))
#
#         elif from_driver == 'localfs' and to_driver == 'db':
#             return(Legacy._converter_localfs_to_db(myconfig))
#
#         else:
#             raise Exception("no converter available for archive driver from="+str(from_driver)+" to="+str(to_driver))
#
#         return(False)
#
#     @staticmethod
#     def _converter_db_to_localfs(myconfig):
#         if 'archive_data_dir' not in myconfig:
#             raise Exception("conversion to localfs from db requires archive_data_dir to be specified in config.yaml, cannot proceed")
#
#         with db.session_scope() as dbsession:
#             logger.debug("running archive driver converter (db->localfs")
#             # need to check if any archive records DO have the document field populated, and if so try to export to localfs
#             archive_matches = db_archivedocument.list_all_notempty(session=dbsession)
#             for archive_match in archive_matches:
#                 userId = archive_match['userId']
#                 bucket = archive_match['bucket']
#                 archiveid = archive_match['archiveId']
#                 archive_record = db_archivedocument.get(userId, bucket, archiveid, session=dbsession)
#                 db_data = json.loads(archive_record['jsondata'])
#
#                 logger.debug("document data - converting DB->driver: " + str([userId, bucket, archiveid]))
#                 dataref = write_archive_file(userId, bucket, archiveid, db_data, driver_override='localfs')
#                 with db.session_scope() as subdbsession:
#                     db_archivedocument.add(userId, bucket, archiveid, archiveid+".json", {'jsondata': "{}"}, session=subdbsession)
#
#             logger.debug("archive driver converter complete")
#         return(True)
#
#     @staticmethod
#     def _converter_localfs_to_db(myconfig):
#         if 'archive_data_dir' not in myconfig:
#             raise Exception("conversion to db from localfs requires archive_data_dir (location of previous localfs archive data) to be specified in config.yaml, cannot proceed")
#
#         with db.session_scope() as dbsession:
#             logger.debug("running archive driver converter (localfs->db)")
#             # need to check if any archive records do not have the document field populated, and if so try to import from localfs
#             dbfilter = {'jsondata': '{}'}
#             archive_matches = db_archivedocument.list_all(session=dbsession, **dbfilter)
#             for archive_match in archive_matches:
#                 userId = archive_match['userId']
#                 bucket = archive_match['bucket']
#                 archiveid = archive_match['archiveId']
#                 try:
#                     fs_data = read_archive_file(userId, bucket, archiveid, driver_override='localfs')
#                 except Exception as err:
#                     logger.debug("no data: " + str(err))
#                     fs_data = None
#
#                 if fs_data:
#                     logger.debug("document data - converting driver->DB: " + str([userId, bucket, archiveid]))
#                     with db.session_scope() as subdbsession:
#                         db_archivedocument.add(userId, bucket, archiveid, archiveid+".json", {'jsondata': json.dumps(fs_data)}, session=subdbsession)
#                     delete_archive_file(userId, bucket, archiveid, driver_override='localfs')
#
#             logger.debug("archive driver converter complete")
#         return(True)
