require '../lib/tacacs_plus.rb'
require 'yaml'

puts "CLIENT/SERVER DIALOGS\nTABLE OF CONTENTS\n\n"

chapter = 1
["malformed_packets", "authentication", "authorization", "accounting", "cisco_captures"].each do |dir|
    Dir.chdir(dir)
    puts "Chapter #{chapter}: #{dir}"
    Dir.glob("*.yaml").each do |file|
        pad = '.' * (60 - file.length)
        dialog = YAML.load_file(file)
        puts "   #{file}#{pad} #{dialog[:description]}"
    end
    Dir.chdir('../')
    print "\n\n"
    chapter += 1
end


__END__
