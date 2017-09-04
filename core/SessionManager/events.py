"""
This module has classes related to events.
"""
from time import strftime
from enum import Enum

event_symbols = {
                    -1  : "[-]",
                    0   : "[/]",
                    1   : "[+]"
                }

def parse_event_line(line):
    inv_symbols = {v: k for k, v in event_symbols.iteritems()}
    try:
        event_day_time = line.split("]")[0][1:]
        event_type = inv_symbols[line[len(event_day_time) + 2 : len(event_day_time) + 5]]
        event_message = line[len(event_day_time) + 7:]
        return Event(event_day_time, event_type, message)
    except:
        return None


class EventType(Enum):
    Unsuccessful    = -1
    Neutral         = 0
    Successful      = 1

class Event(object):
    def __init__(self, event_type, message, event_day_time = None):
        self.event_day_time = strftime("%H:%M:%S") if not event_day_time else event_day_time
        self.event_type = event_type
        self.message = message

    def __str__(self):
        return "[{time}]{symbol} - {message}".format(   time = self.event_day_time,
                                                        symbol = event_symbols[self.event_type],
                                                        message = self.message  )

class UnsuccessfulEvent(Event):
    def __init__(self, message):
        super(UnsuccessfulEvent, self).__init__(EventType.Unsuccessful, message)

class NeutralEvent(Event):
    def __init__(self, message):
        super(UnsuccessfulEvent, self).__init__(EventType.Neutral, message)

class SuccessfulEvent(Event):
    def __init__(self, message):
        super(UnsuccessfulEvent, self).__init__(EventType.Successful, message)
