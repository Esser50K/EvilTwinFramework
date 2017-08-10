"""
This class is responsible for printing 
information tables according to filters
"""
from prettytable import PrettyTable

class InfoPrinter(object):

    def __init__(self):
        self.info_filter = InfoFilter()
        self.args_info = {} # key: (args, headers)

    def add_info(self, key, values, args_to_print, headers):
        if len(args_to_print) != len (headers):
            print "[-] Incompatible header and args_to_print size for '{}'".format(key)
            return

        self.info_filter.add_info(key, values)
        self.args_info[key] = (args_to_print, headers)

    def print_info(self, key, filter_string = None):
        filtered_objs = self.info_filter.get_info(key, filter_string)
        args, headers = self.args_info[key]
        table = PrettyTable(headers)

        for obj in filtered_objs:
            obj_arg_list = []
            for arg in args:
                val = obj.__dict__[arg]
                if type(val) is list or type(val) is set:
                    val = sorted([x for x in val if x is not None]) # Remove Nones
                    val = "\n".join(val).encode("utf-8").strip()

                # Try parse it as int so the output is sorted correctly
                try:
                    obj_arg_list.append(int(val))
                except:
                    if type(val) is str:
                        obj_arg_list.append(val.encode("utf-8"))
                    else:
                        obj_arg_list.append(str(val).encode("utf-8"))
            table.add_row(obj_arg_list)

        sorted_prettytable = table.get_string(sortby=headers[0])
        print sorted_prettytable
        return filtered_objs



class InfoFilter(object):

    def __init__(self):
        self._info = {"all": {}}    # key: list
        self_info_headers = {}      # key: list
        self.obj_filter = ObjectFilter()

    def add_info(self, key, values): # value must be list
        if type(values) is not list:
            print "[-] Error cannot add '{}' because values is not a list".format(key)
            return False

        self._info[key] = values
        self._info["all"][key] = values
        return True

    def get_all_info(self, filter_string):
        pass

    def get_info(self, key, filter_string):
        try:
            self._info[key]
        except KeyError:
            print "[-] No info for '{}'".format(key)
            return []

        return self.obj_filter.filter(self._info[key], filter_string)


class ObjectFilter(object):

    def __init__(self):
        self.AND_keyword = "only"
        self.OR_keyword = "where"

    def filter(self, objlist, filter_string):
        if not filter_string or filter_string == "": #NoFilters
            return objlist

        AND_filter, filter_map = self._parse_filter_string(filter_string)

        if AND_filter:
            return self._AND_filter(objlist, filter_map)
        else:
            return self._OR_filter(objlist, filter_map)

    def _AND_filter(self, objlist, filter_map):
        filtered_objlist = []
        for obj in objlist:
            add = True
            for filter_arg in filter_map:
                try:
                    for filter_value in filter_map[filter_arg]:
                        if not (type(obj.__dict__[filter_arg]) is list or type(obj.__dict__[filter_arg]) is set):
                            try:
                                if int(filter_value) != int(obj.__dict__[filter_arg]):
                                    add = False
                                    break
                            except:
                                if str(filter_value).lower() not in str(obj.__dict__[filter_arg]).lower():
                                    add = False
                                    break
                        else:
                            if filter_value not in obj.__dict__[filter_arg]:
                                add = False
                                break
                except KeyError: # Don't judge if obj does not have a certain attribute
                    pass

            if add:
                filtered_objlist.append(obj)

        return filtered_objlist

    def _OR_filter(self, objlist, filter_map):
        filtered_objlist = []
        for obj in objlist:
            for filter_arg in filter_map:
                try:
                    for filter_value in filter_map[filter_arg]:
                        if not (type(obj.__dict__[filter_arg]) is list or type(obj.__dict__[filter_arg]) is set):
                            try:
                                if int(filter_value) == int(obj.__dict__[filter_arg]):
                                    filtered_objlist.append(obj)
                                    break
                            except:
                                if str(filter_value).lower() in str(obj.__dict__[filter_arg]).lower():
                                    filtered_objlist.append(obj)
                                    break
                        else:
                            for element in obj.__dict__[filter_arg]:
                                if str(filter_value).lower() in str(obj.__dict__[filter_arg]).lower():
                                    filtered_objlist.append(obj)
                                    break
                except KeyError: # Don't judge if obj does not have a certain attribute
                    pass

        return filtered_objlist



    # returns a map of attributes with filter key and filter type (AND or OR filter)
    def _parse_filter_string(self, filter_string):
        split_filter = filter_string.split()
        filter_type = split_filter[0]
        filter_args = "".join(split_filter[1:])

        filter_map = self._parse_filter_args(filter_args)

        AND_filter = filter_type == self.AND_keyword
            
        return (AND_filter, filter_map)

    # returns a map of attributes with filter key
    def _parse_filter_args(self, filter_args):
        split_args = filter_args.split(",")
        filter_map = {}

        for arg in split_args:
            try:
                key, value = arg.split("=")
                filter_map[key].append(value)
            except KeyError:
                filter_map[key] = [value]
            except Exception:
                print "[-] Unable to parse arg '{}'".format(arg)

        return filter_map

