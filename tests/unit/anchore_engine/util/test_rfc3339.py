import datetime

import anchore_engine.utils as utils

rfc3339_examples = [
    ("2001-02-03T04:05:06Z", {'dt': datetime.datetime(2001, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc),'epoch': 981173106}),
    ("2001-02-03T04:05:06:000007Z", {'dt': datetime.datetime(2001, 2, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc),'epoch': 981173106}),
    ("2001-02-03T04:05:06.000007Z", {'dt': datetime.datetime(2001, 2, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc),'epoch': 981173106}),
]

epoch_examples = [
    (981173106, {'dt': datetime.datetime(2001, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc), 'rfc3339': "2001-02-03T04:05:06Z"}),
    (981173106.000007,{'dt': datetime.datetime(2001, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc), 'rfc3339': "2001-02-03T04:05:06Z"}),
]

dt_examples = [
    (datetime.datetime(2001, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc), {'epoch': 981173106, 'rfc3339': "2001-02-03T04:05:06Z"}),
    (datetime.datetime(2001, 2, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc), {'epoch': 981173106, 'rfc3339': "2001-02-03T04:05:06Z"}),
]

assert_targets = {'dt': datetime.datetime(2001, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc),'epoch': 981173106,'rfc3339': "2001-02-03T04:05:06Z"}


def test_rfc3339():

    # parsing/validation and conversion symmetry
    for rfc_str,assert_targets in rfc3339_examples:
        print ("testing input string: {}".format(rfc_str))
        rc = utils.rfc3339str_to_epoch(rfc_str)
        print ("\trfc3339_to_epoch: {}".format(rc))
        assert(rc == assert_targets['epoch'])
        print("\tepoch assertion passed")

        rc = utils.rfc3339str_to_datetime(rfc_str)
        print ("\trfc3339_to_datetime: {}".format(rc))
        assert(rc == assert_targets['dt'])
        print("\tdatetime assertion passed")

    for epoch,assert_targets in epoch_examples:
        print ("testing input epoch: {}".format(epoch))
        rc = utils.epoch_to_rfc3339(epoch)
        print ("\tepoch_to_rfc3339: {}".format(rc))
        assert(rc == assert_targets['rfc3339'])
        print("\tdatetime assertion passed")

    for dt,assert_targets in dt_examples:
        print ("testing input datetime: {}".format(dt))
        rc = utils.datetime_to_rfc3339(dt)
        print ("\tdatetime_to_rfc3339: {}".format(rc))        
        assert(rc == assert_targets['rfc3339'])
        print("\tdatetime assertion passed")        

def test_dt_to_epoch():
    for dt, assert_targets in dt_examples:
        print("testing input datetime: {}".format(dt))
        epoch = utils.datetime_to_epoch(dt)
        print("\tdatetime_to_epoch: {}".format(epoch))
        assert(epoch == assert_targets['epoch'])
