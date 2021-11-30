#!/usr/bin/env python3

import sys
import os

me = os.path.basename(sys.argv[0])
iAmModule = os.path.splitext(me)[0]
if me == "__init__.py":
    iAmModule = "argparsebetter"


def error(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class BetterArgParser:
    '''
    Parse mutually exclusive optional arguments and other things that
    argparse either can't do or does only with obfuscated code--See:
    - <https://stackoverflow.com/questions/59773946/argparse-required-add-mutually-exclusive-group-parameters-list-as-optional>
      Exclusive group parameters can't be optional or need some sort of
      callback to make work.
      - <https://stackoverflow.com/questions/40324356/python-argparse-choices-with-a-default-choice>
        doesn't solve the issue since the subcommand is still required.

    Public members:
    description -- The description of the program for which args are
        being parsed.
    cmd -- The name of the command used to run the program described.

    Private members:
    _parsing_args -- Only exists for showing the current set of args.
        Do not use this in logic since the only reason to do that would
        be for lookahead and that is not recommended since it breaks
        logic.
    _active_values -- values that were ever set on the current run of
        parse (reset on initialize or unparse).
    '''
    def __init__(self, description=None):
        self.cmd = "<this_program> "
        if len(sys.argv) > 0:
            self.cmd = os.path.basename(sys.argv[0])
        self._arg_metas = {}
        self._lookup_args = {}
        self.groups = []
        self.verbose = False
        self.description = None
        self._groups = {}
        self.unparse()

    def get_aliases(self, arg):
        aliases = []
        meta = self._arg_metas[arg]
        for other_arg, other_meta in self._arg_metas.items():
            if arg == other_arg:
                continue
            if other_meta['metavar'] == meta['metavar']:
                aliases.append(other_arg)
        if len(aliases) < 1:
            return None
        return aliases

    def debug(self, msg):
        if not self.verbose:
            return
        sys.stderr.write("{}\n".format(msg))
        sys.stderr.flush()

    def unparse(self):
        self._values = {}
        self._prev_arg = None
        self._save_key = None
        self._default_key = None
        self._parsing_args = None
        self._active_values = set([])

    def append_as(self, name, value):
        if self._values.get(name) is None:
            self._values[name] = [value]
        else:
            self._values[name].append(value)

    def append_to_group(self, name, value):
        if self._groups.get(name) is None:
            self._groups[name] = [value]
        else:
            self._groups[name].append(value)

    def append_lookup(self, metavar, arg):
        '''
        Add the arg to the list of args that affect metavar.
        '''
        if self._lookup_args.get(metavar) is None:
            self._lookup_args[metavar] = [arg]
        else:
            self._lookup_args[metavar].append(arg)

    def add_argument(self, arg, metavar=None, value=None, help=None,
            group=None, required=False, as_list=False, after=None,
            collect=False, mutually_exclusive=True):
        '''
        Keyword arguments:
        group -- reserved for future use (not implemented fully)
        collect -- Collect a list instead of setting a value.
        mutually_exclusive -- If multiple args affect the same metavar,
            do not allow more than one of the args when
            mutually_exclusive is True.
        '''
        if arg is None:
            raise ValueError("arg must not be None.")
        name = metavar
        if name is None:
            # Leave metavar as None for logic further down.
            name = arg
        if self._arg_metas.get(arg):
            raise ValueError("You already defined the {} arg."
                             "".format(arg))
        if name is None:
            raise RuntimeError("Name must not be None.")
        self._arg_metas[arg] = {
            'metavar': name,
            'value': value,
            'help': help,
            'group': group,
            'required': required,
            'as_list': as_list,
            'after': after,
            'collect': collect,
            'mutually_exclusive': mutually_exclusive,
        }
        if group is not None:
            self.append_to_group(group, arg)
        if metavar is not None:
            self.append_lookup(metavar, arg)

    def print_help(self):
        done_args = []
        o_helps = []
        r_helps = []
        # for name, args in self._lookup_args.items():
        args = self._arg_metas.keys()
        o_help_names = []
        r_help_names = []
        for arg in args:
            if arg in done_args:
                continue
            meta = self._arg_metas[arg]
            if meta.get('required') is True:
                r_help_names.append(arg)
            else:
                o_help_names.append(arg)
            arg_msg = arg + "  -- "
            help = meta.get('help')
            value = None
            if help is not None:
                arg_msg += " {}".format(help)
            else:
                if meta.get('collect') is True:
                    arg_msg += (" Use {} again to add more terms."
                                "".format(arg))
                if meta['metavar'] != arg:
                    value = meta.get('value')
                    if value is not None:
                        arg_msg += (" Set {} to {}."
                                    "".format(meta['metavar'], value))
            aliases = self.get_aliases(arg)
            if aliases is not None:
                for alias in aliases:
                    done_args.append(alias)
                    other_meta = self._arg_metas[alias]
                    help = other_meta.get('help')
                    other_value = other_meta.get('value')
                    if help is not None:
                        arg_msg += (" Alternatively use {}: {}"
                                    "".format(alias, help))
                    elif other_value != value:
                        arg_msg += (" Alternatively use {} to set {} to {}."
                                    "".format(alias, other_meta['metavar'], other_value))
                    else:
                        arg_msg += (" Alternatively use {}."
                                    "".format(alias))
            if meta['required']:
                r_helps.append(arg_msg)
            else:
                o_helps.append(arg_msg)
            done_args.append(arg)

        usage_msg = "usage" + self.cmd
        if len(r_help_names) > 0:
            r_helps_msg = " <"+",".join(r_help_names) + ">"
            usage_msg += r_helps_msg
        if len(o_help_names) > 0:
            o_helps_msg = " {"+",".join(o_help_names) + "}"
            usage_msg += o_helps_msg

        print(usage_msg)
        if self.description is not None:
            print("")
            print("{}".format(self.description))

        if len(o_helps) > 0:
            print("")
            print("optional arguments:")
            for o_help in o_helps:
                print(o_help)
        if len(r_helps) > 0:
            print("")
            print("required arguments:")
            for r_help in r_helps:
                print(r_help)

    def is_arg(self, name):
        if name is None:
            raise ValueError("Name must not be None.")
        return self._arg_metas.get(name) is not None

    def formatOutOfSeq(self, got, expected_first):
        return "You can't do {} before {}".format(got, expected_first)

    def _parse_arg(self, arg):
        p = "  "  # line prefix

        if self._save_key is not None:
            real_args = self._lookup_args.get(self._save_key)
            meta = None
            if real_args is not None:
                if len(real_args) > 0:
                    self._arg_metas.get(real_args[0])
            if meta is not None:
                if meta.get('mutually_exclusive') is True:
                    if self._save_key in self._active_values:
                        raise ValueError("{} is already set."
                                         "".format(self._save_key))
            self._values[self._save_key] = arg
            self._active_values.add(self._save_key)
            self._save_key = None
            return True
        meta = self._arg_metas.get(arg)
        if meta is None:
            if self._default_key is not None:
                # Collect any misplaced params as real params
                # (store them in the list named self._default_key).
                self.append_as(self._default_key, arg)
                return True
            else:
                self.debug(p+"{} is not an arg and"
                           " there is no default_key (command: {})."
                           "".format(arg, self._parsing_args))
                return False
        after = meta.get('after')
        if after is not None:
            if self._values.get(after) is None:
                raise ValueError(self.formatOutOfSeq(arg, after))
        value = meta.get('value')
        if value is None:
            # Use the next arg as the value.
            self._save_key = meta.get('metavar')
            if self._save_key is None:
                self._save_key = arg
        else:
            self._values[arg] = value
        self._prev_arg = arg
        return True

    def parse_args(self, args, skip_0=True, default_key=None):
        '''
        Keyword arguments:
        skip_0 -- Skip args[0] such as if it is sys.argv[0]
            (the program itself).
        default_key -- If any arguments do not match specified
            criteria, collect them in a list of this name.
        '''
        self._default_key = default_key
        self._parsing_args = args
        if skip_0:
            args = args[1:]
        for arg in args:
            if not self._parse_arg(arg):
                error("{} is not a valid argument.".format(arg))
        if self._save_key is not None:
            raise ValueError("You must specify a value after {}"
                             "".format(self._save_key))
        self._prev_arg = None
        self._parsing_args = None

    def set_verbose(self, verbose):
        self.verbose = verbose
        v_msg = "on" if verbose else "off"
        print("* verbose mode is {}".format(v_msg))


def tests():
    parser = BetterArgParser()
    parser.add_argument('--verbose', metavar='verbose', value=True)
    parser.add_argument('--debug', metavar='verbose', value=True)
    state_help = ("Choose to show issues where state is open (the"
                  " default query depends on the which web API"
                  " you are targeting).")
    parser.add_argument('open', metavar='state', value='open',
                        help=state_help)
    parser.add_argument('closed', metavar='state', value='closed')
    # ^ Mutually exclusive is True by default, so "closed open" should
    #   raise ValueError (See `"closed", "open"` below).
    parser.add_argument('find', collect=True)
    parser.add_argument('AND', metavar='find', after="find",
                        collect=True,
                        help=("Use AND after find."))
    error("* testing the help system:")
    parser.print_help()
    print("")
    print("  * OK (If usage is displayed above).")
    print("")
    parser.set_verbose(True)

    sys.stderr.write("* testing collected undefined arg then specific arg...")
    parser.parse_args(
        ["enissue.py", "Bucket_Game", "open"],
        default_key="labels",
    )
    error("OK")
    parser.unparse()

    sys.stderr.write("  * testing another...")
    parser.parse_args(
        ["enissue.py", "Bucket_Game", "closed"],
        default_key="labels",
    )
    error("OK")
    parser.unparse()

    sys.stderr.write("* testing an arg that requires a value...")
    parser.parse_args(
        ["enissue.py", "Bucket_Game", "find", "mobs"],
        default_key="labels",
    )
    error("OK")
    parser.unparse()

    sys.stderr.write("  * testing it without a value...")
    try:
        parser.parse_args(
            ["enissue.py", "Bucket_Game", "find"],
            default_key="labels",
        )
        raise RuntimeError("Find has no default value, so using find without a value should raise ValueError but didn't.")
    except ValueError as ex:
        error("OK (raised ValueError as expected)")
    parser.unparse()

    sys.stderr.write("* testing an arg with a prerequisite...")
    parser.parse_args(
        ["enissue.py", "Bucket_Game", "find", "mobs", "AND", "walk"],
        default_key="labels",
    )
    error("OK")
    parser.unparse()

    # Should raise ValueError:
    sys.stderr.write("  * testing it before the expected arg...")
    expectedEx = parser.formatOutOfSeq("AND", "find")
    try:
        parser.parse_args(
            ["enissue.py", "Bucket_Game", "AND", "mobs"],
            default_key="labels",
        )
        raise RuntimeError("Using AND before find should raise a ValueError but didn't.")
    except ValueError as ex:
        assert expectedEx in str(ex), "The only ValueError should be " + expectedEx
    error("OK (raised the correct ValueError)")
    parser.unparse()

    # Should raise ValueError:
    sys.stderr.write("* testing two args with the same metavar (with mutually_exclusive=True by default)...")
    try:
        parser.parse_args(
            ["enissue.py", "Bucket_Game", "bug", "closed", "open"],
            default_key="labels",
        )
        raise RuntimeError("mutually_exclusive=True by default so using two args with the same metavar should raise a ValueError but didn't.")
    except ValueError:
        error("OK (raised ValueError as expected)")
    expected_labels_s = "Bucket_Game,bug"
    assert ",".join(parser._values['labels']) == expected_labels_s, "Args without context should be appended as labels."
    error("OK (labels={})".format(expected_labels_s))


testMsg = """

{module}

INFO: You ran the {module} module as the main program, so only tests will run.
"""


if __name__ == "__main__":
    print(testMsg.format(module=iAmModule))
    tests()
    print("All tests passed.")
