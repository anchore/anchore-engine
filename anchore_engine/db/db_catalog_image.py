from sqlalchemy import desc
import time

from anchore_engine import db
import anchore_engine.db.db_catalog_image_docker
from anchore_engine.db import CatalogImage, CatalogImageDocker
from anchore_engine.subsys import logger

def add_record(input_image_record, session=None):
    if not session:
        session = db.Session

    image_record = {}
    image_record.update(input_image_record)

    image_record.pop('created_at', None)
    image_record.pop('last_updated', None)

    our_result = session.query(CatalogImage).filter_by(imageDigest=image_record['imageDigest'], userId=image_record['userId'], image_type=image_record['image_type']).first()
    if not our_result:
        # add the image detail
        image_detail = image_record.pop('image_detail')
        if image_record['image_type'] == 'docker':
            # add the detail records
            for tag_record in image_detail:
                rc = db.db_catalog_image_docker.add_record(tag_record, session=session)

        our_result = CatalogImage(**image_record)
        session.add(our_result)
    
    return(True)

def update_record(input_image_record, session=None):
    if not session:
        session = db.Session

    image_record = {}
    image_record.update(input_image_record)

    image_record.pop('created_at', None)
    image_record.pop('last_updated', None)

    our_result = session.query(CatalogImage).filter_by(imageDigest=image_record['imageDigest'], userId=image_record['userId'], image_type=image_record['image_type']).first()
    if our_result:
        image_detail = image_record.pop('image_detail')
        if image_record['image_type'] == 'docker':

            # add the detail records
            imageId = None
            for tag_record in image_detail:
                rc = db.db_catalog_image_docker.add_record(tag_record, session=session)
                rc = db.db_catalog_image_docker.update_record(tag_record, session=session)
                if 'imageId' in tag_record and tag_record['imageId']:
                    imageId = tag_record['imageId']

            # handle case where there may have been new image_detail records added before imageId element was ready, sync all image_details with latest imageId
            try:
                if imageId:
                    all_tag_records = db.db_catalog_image_docker.get_alltags(image_record['imageDigest'], image_record['userId'], session=session)
                    for tag_record in all_tag_records:
                        if 'imageId' not in tag_record or ('imageId'  in tag_record and not tag_record['imageId']):
                            tag_record['imageId'] = imageId
                            rc = db.db_catalog_image_docker.update_record(tag_record, session=session)
            except Exception as err:
                logger.warn("unable to update all image_details with found imageId: " + str(err))

        our_result.update(image_record)
    
    return(True)

def update_record_image_detail(input_image_record, updated_image_detail, session=None):
    if not session:
        session = db.Session

    image_record = {}
    image_record.update(input_image_record)

    image_record.pop('created_at', None)
    image_record.pop('last_updated', None)

    if image_record['image_type'] == 'docker':
        for tag_record in updated_image_detail:
            if tag_record not in image_record['image_detail']:
                image_record['image_detail'].append(tag_record)
                return(update_record(image_record, session=session))

    return(image_record)

if False:
    def add(imageDigest, userId, image_type, dbobj={}, image_data={}, session=None):
        if not session:
            session = db.Session

        dbobj.pop('created_at', None)
        dbobj.pop('last_updated', None)

        our_result = session.query(CatalogImage).filter_by(imageDigest=imageDigest, userId=userId, image_type=image_type).first()
        if not our_result:
            if image_type == 'docker' and image_data:
                rc = db.db_catalog_image_docker.add(imageDigest, userId, image_data['tag'], registry=image_data['registry'], user=image_data['user'], repo=image_data['repo'], digest=image_data['digest'], imageId=image_data['imageId'], dockerfile=image_data['dockerfile'], session=session)

            our_result = CatalogImage(imageDigest=imageDigest, userId=userId, image_type=image_type)

            our_result.update(dbobj)
            session.add(our_result)
        else:
            our_result.update(dbobj)
            if image_type == 'docker' and image_data:
                rc = db.db_catalog_image_docker.update(imageDigest, userId, image_data['tag'], registry=image_data['registry'], user=image_data['user'], repo=image_data['repo'], digest=image_data['digest'], imageId=image_data['imageId'], dockerfile=image_data['dockerfile'], session=session)

        return(True)

    def update(imageDigest, userId, image_type, dbobj={}, image_data={}, session=None):
        return(add(imageDigest, userId, image_type, dbobj=dbobj, image_data=image_data, session=session))

def get(imageDigest, userId, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(CatalogImage).filter_by(imageDigest=imageDigest, userId=userId).order_by(desc(CatalogImage.created_at)).first()
    if result:
        dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret = dbobj
        if dbobj['image_type'] == 'docker':
            imgobj = db.db_catalog_image_docker.get_alltags(imageDigest, userId, session=session)
            ret['image_detail'] = imgobj

    return(ret)

def get_created_at(record):
    if 'created_at' in record and record['created_at']:
        return(record['created_at'])
    return(0)

def get_byimagefilter(userId, image_type, dbfilter={}, onlylatest=False, session=None):
    if not session:
        session = db.Session

    ret = []

    ret_results = []
    if image_type == 'docker':
        results = db.db_catalog_image_docker.get_byfilter(userId, session=session, **dbfilter)
        for result in results:
            imageDigest = result['imageDigest']
            dbobj = get(imageDigest, userId, session=session)
            ret_results.append(dbobj)
            
    sorted_results = sorted(ret_results, key=get_created_at, reverse=True)

    if not onlylatest:
        ret = sorted_results
    else:
        if sorted_results:
            ret = [sorted_results[0]]
        else:
            ret = []

    return(ret)

def get_all_digtags0(userId, session=None):
    
    ret = []
    results = session.query(CatalogImage.imageDigest, CatalogImageDocker.registry, CatalogImageDocker.repo, CatalogImageDocker.tag).filter(CatalogImage.imageDigest == CatalogImageDocker.imageDigest).filter_by(userId=userId)
    for result in results:
        ret.append(result)

    return(ret)

def get_all_digtags1(userId, session=None):
    
    ret = []
    results = session.query(CatalogImageDocker.imageDigest, CatalogImageDocker.registry, CatalogImageDocker.repo, CatalogImageDocker.tag).filter_by(userId=userId)
    #ret = list(results.values())
    ret = list(results)
    #for result in results:
    #    ret.append(result)

    return(ret)

def get_all_byuserId(userId, session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(CatalogImage).filter_by(userId=userId).order_by(desc(CatalogImage.created_at))
    if results:
        # get all the tags in single DB query, hash by imageDigest
        alltags = db.db_catalog_image_docker.get_all(userId, session=session)
        tagdata = {}
        for tag in alltags:
            if tag['imageDigest'] not in tagdata:
                tagdata[tag['imageDigest']] = []
            tagdata[tag['imageDigest']].append(tag)

        for result in results:
            dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
            #dbobj = result.__dict__
            #dbobj.pop('_sa_instance_state', None)

            imageDigest = dbobj['imageDigest']
            if dbobj['image_type'] == 'docker':
                if imageDigest in tagdata:
                    dbobj['image_detail'] = tagdata[imageDigest]
                else:
                    dbobj['image_detail'] = []                

                #imgobj = db.db_catalog_image_docker.get_alltags(imageDigest, userId, session=session)
                #dbobj['image_detail'] = imgobj
            ret.append(dbobj)
    return(ret)

def get_all_iter(session=None):
    if not session:
        session = db.Session

    for top_result in session.query(CatalogImage.imageDigest, CatalogImage.userId).order_by(desc(CatalogImage.created_at)):
        result = session.query(CatalogImage).filter_by(imageDigest=top_result.imageDigest, userId=top_result.userId).first()
        dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        imageDigest = dbobj['imageDigest']
        userId = dbobj['userId']
        if dbobj['image_type'] == 'docker':
            imgobj = db.db_catalog_image_docker.get_alltags(imageDigest, userId, session=session)
            dbobj['image_detail'] = imgobj
        yield dbobj
        #ret.append(dbobj)

    #return(ret)    

def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(CatalogImage).order_by(desc(CatalogImage.created_at))
    if results:
        for result in results:
            dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
            imageDigest = dbobj['imageDigest']
            userId = dbobj['userId']
            if dbobj['image_type'] == 'docker':
                imgobj = db.db_catalog_image_docker.get_alltags(imageDigest, userId, session=session)
                dbobj['image_detail'] = imgobj
            ret.append(dbobj)

    return(ret)

def get_byfilter(userId, session=None, **kwargs):
    if not session:
        session = db.Session

    ret = []

    kwargs['userId'] = userId

    results = session.query(CatalogImage).filter_by(**kwargs).order_by(desc(CatalogImage.created_at))
    if results:
        for result in results:
            dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
            imageDigest = dbobj['imageDigest']
            userId = dbobj['userId']
            if dbobj['image_type'] == 'docker':
                imgobj = db.db_catalog_image_docker.get_alltags(imageDigest, userId, session=session)
                dbobj['image_detail'] = imgobj
            ret.append(dbobj)

    return(ret)

def delete(imageDigest, userId, session=None):
    if not session:
        session = db.Session

    our_results = session.query(CatalogImage).filter_by(imageDigest=imageDigest, userId=userId)
    for result in our_results:
        session.delete(result)

    our_results = session.query(CatalogImageDocker).filter_by(imageDigest=imageDigest, userId=userId)
    for result in our_results:
        session.delete(result)

#    try:
#        session.commit()
#    except Exception as err:
#        raise err
#    finally:
#        session.rollback()

    return(True)
