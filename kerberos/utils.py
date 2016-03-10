from datetime import datetime


UPDATE_TIMEOUT = 5
TIME_TO_LIVE_SESSION_KEY = 10 ** 6

TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
max_allowed_time_difference = 10 * 60


def get_timestamp():
    return datetime.now().strftime(TIME_FORMAT)


def check_timestamp(timestamp, time_to_live=max_allowed_time_difference):
    time_difference = datetime.now() - datetime.strptime(timestamp, TIME_FORMAT)
    return time_difference.total_seconds() < time_to_live
