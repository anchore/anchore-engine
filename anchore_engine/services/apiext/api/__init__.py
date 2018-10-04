import enum


class AuthActions(enum.Enum):
    """
    Enumeration of the authorization actions for the external API
    """

    list_images = 'listImages'
    create_image = 'createImage'
    delete_image = 'deleteImage'
    get_image = 'getImage'
    update_image = 'updateImage'

    list_events = 'listEvents'
    get_event = 'getEvent'
    create_event = 'createEvent'
    delete_event = 'deleteEvent'
    flush_events = 'deleteEvents'

    list_policies = 'listPolicies'
    create_policy = 'createPolicy'
    delete_policy = 'deletePolicy'
    get_policy = 'getPolicy'
    update_policy = 'updatePolicy'

    list_evaluations = 'listImageEvaluations'
    create_evaluation = 'createImageEvaluation'
    delete_evaluation = 'deleteImageEvaluation'
    get_evaluation = 'getImageEvaluation'
    update_evaluation = 'updateImageEvaluation'

    list_registries = 'listRegistries'
    create_registry = 'createRegistry'
    delete_registry = 'deleteRegistry'
    get_registry = 'getRegistry'
    update_registry = 'updateRegistry'

    list_repositories = 'listRepositories'
    create_repository = 'createRepository'
    delete_repository = 'deleteRepository'
    get_repository = 'getRepository'
    update_repository = 'updateRepository'

    list_subscriptions = 'listSubscriptions'
    create_subscription = 'createSubscription'
    delete_subscription = 'deleteSubscription'
    get_subscription = 'getSubscription'
    update_subscription = 'updateSubscription'

    list_services = 'listServices'
    add_service = 'createService'
    delete_service = 'deleteService'
    get_service = 'getService'
    get_status = 'getStatus'

    list_feeds = 'listFeeds'
    update_feeds = 'updateFeeds'

    prune = 'runPrune'

    list_accounts = 'listAccounts'
    create_account = 'createAccount'
    update_account = 'updateAccount'
    delete_account = 'deleteAccount'
    get_account = 'getAccount'

    list_users = 'listUsers'
    get_user = 'getUser'
    create_user = 'createUser'
    delete_user = 'deleteUser'
    update_user = 'updateUser'
