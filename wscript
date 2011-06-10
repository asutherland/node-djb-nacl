srcdir = '.' # 1.6: top
blddir = 'build' # 1.6: out
VERSION = '0.0.1'

def set_options(opt):
  opt.tool_options('compiler_cxx')

def configure(conf):
  conf.check_tool('compiler_cxx')
  conf.check_tool('node_addon')

PLATFORM_MAP = {'x86_64': 'amd64', 'i386': 'x86', 'i686': 'x86'}

def build(bld):
  import os.path, Utils
  # nacl puts its build output in nacl/build/`hostname -s`...
  libnacl_build_dir = os.path.join('nacl/build')
  libnacl_inc_dir = os.path.join(libnacl_build_dir, 'include')
  libnacl_lib_dir = os.path.join(libnacl_build_dir)

  ## I tried to do something like the following; it did not go so well and
  ## there was no useful error reporting, so instead...
  #libnacl = bld(rule='./nacl/do', name='LIBNACL',
  #              target=libnacl_lib_path)
  ## this:
  if not os.path.exists(os.path.join(libnacl_lib_dir, 'libnacl.a')):
    print 'Forcing nacl build'
    Utils.exec_command('cd nacl; waf configure; waf build')
    print 'nacl built'
  else:
    print 'nacl already built'
  ## I think you can agree that given that "do" is a shell script, there's
  ## not really any loss of elegance by me doing the above.  That said, feel
  ## free to fix this deficiency.

  obj = bld.new_task_gen('cxx', 'shlib', 'node_addon')
  obj.target = 'nacl'
  obj.source = 'src/nacl_node.cc'

  # we used to have cram randombytes in when it was not part of the lib...
  #obj.add_obj_file(os.path.join(libnacl_lib_dir, 'randombytes.o'))
  obj.includes = [libnacl_inc_dir]
  obj.libpath = [os.path.join('..', libnacl_lib_dir)]
  obj.staticlib = 'nacl'

# We are cribbing this from bcrypt's shutdown because it's not clear to me
# how we otherwise would get our lib in here...
def shutdown():
  import Options
  from os import unlink, symlink
  from os.path import exists, islink
  t = 'nacl.node'
  if Options.commands['clean']:
    if exists(t): unlink(t)
  if Options.commands['build']:
    if exists('build/default/' + t) and not exists(t):
      symlink('build/default/' + t, t)
