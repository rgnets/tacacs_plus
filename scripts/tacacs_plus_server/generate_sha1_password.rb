require 'digest/sha1'

salt = (1..32).collect { (i = Kernel.rand(62); i += ((i < 10) ? 48 : ((i < 36) ? 55 : 61 ))).chr }.join

print "Password to encrypt: "
pw = STDIN.gets.chomp!
sha1_pw = Digest::SHA1.hexdigest(pw + salt)
print "\n---\nSalt: #{salt}\nSHA1 password: #{sha1_pw}\n\n"
__END__