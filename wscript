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
  # nacl puts its build output in nacl/build/`hostname -s`...
  import subprocess, os.path, Utils, platform
  pope = subprocess.Popen(["hostname", "-s"], stdout=subprocess.PIPE)
  hostname = pope.communicate()[0].strip()
  libnacl_arch = PLATFORM_MAP[platform.machine()] # explode on unsupported
  libnacl_build_dir = os.path.join('nacl/build', hostname)
  libnacl_inc_dir = os.path.join(libnacl_build_dir, 'include', libnacl_arch)
  libnacl_lib_dir = os.path.join(libnacl_build_dir, 'lib', libnacl_arch)

  ## I tried to do something like the following; it did not go so well and
  ## there was no useful error reporting, so instead...
  #libnacl = bld(rule='./nacl/do', name='LIBNACL',
  #              target=libnacl_lib_path)
  ## this:
  if not os.path.isdir(libnacl_lib_dir):
    print 'Forcing nacl build (%s)' % (libnacl_arch,)
    Utils.exec_command('cd nacl; ./do')
    print 'nacl built'
  else:
    print 'nacl already built (%s), not invoking nacl/do' % (libnacl_arch,)
  ## I think you can agree that given that "do" is a shell script, there's
  ## not really any loss of elegance by me doing the above.  That said, feel
  ## free to fix this deficiency.

  obj = bld.new_task_gen('cxx', 'shlib', 'node_addon')
  obj.target = 'nacl'
  obj.source = 'src/nacl_node.cc'
  print dir(obj)
  obj.add_obj_file(os.path.join(libnacl_lib_dir, 'randombytes.o'))
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
