#!/usr/bin/env ruby
#Author Hider5
#Date 13 January 2019
#version 1.1
require 'optimist'
require 'nmap/program'
require 'net/http'
W  = "\033[0m"  # white (default)
R  = "\033[31m" # red
G  = "\033[1;32m" # green bold
O  = "\033[33m" # orange
B  = "\033[34m" # blue
P  = "\033[35m" # purple
C  = "\033[36m" # cyan
def banners
	system('printf "██████╗  █████╗ ██╗███████╗███████╗\n██╔══██╗██╔══██╗██║██╔════╝██╔════╝\n██████╔╝███████║██║███████╗█████╗\n██╔══██╗██╔══██║██║╚════██║██╔══╝\n██║  ██║██║  ██║██║███████║███████╗\n╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝\n    " | lolcat')
	a = Time.now.strftime("%d %b %Y_%H:%M:%S")
	puts "#{C}#{a}"
	puts"#{G}"
end
def example(arg)
	if arg[:example]
		puts"
Example :
./#{__FILE__} -s www.site.com
./#{__FILE__} -f /sdcard/target.txt
./#{__FILE__} -i site.com #{R}[Need sudo]#{W}
./#{__FILE__} -l [word] -o /sdcard/wordlist.txt
		"
	end
end
def arguments
	opts = Optimist::options do
		version "#{P}Raise 1.0#{W}"
		opt :single, "Scan full port domain with verbosity", :type => :string
		opt :file, "Input File for fast Scan port with Verbosity", :type => :string
		opt :single_root, "Scan Firewall to find Vulnerabilities with nmap #{R}[Need sudo]#{W}", :type => :string
		opt :letter, "Input word", :type => :string
		opt :output, "Input Path Output", :type => :string
		opt :admin_page_finder, "Find Admin Page Finder", :type => :string
		opt :example, "Example arguments"
	end
end
def single_full_tcp(arg)
	if arg[:single]
		banners
		begin
			Nmap::Program.scan do |nmap|
				nmap.verbose = true
				nmap.ports = '1-65535'
				nmap.targets = "#{arg[:single]}"
			end
		rescue
		end
	end
end

def file_tcp_scan(arg)
	if arg[:file]
		banners
		begin
			Nmap::Program.scan do |nmap|
				nmap.verbose = true
				nmap.target_file = "#{arg[:file]}"
			end
		rescue
		end
	end
end

def scan_firewall_vulnerabilities(arg)
	if arg[:single_root]
		banners
		begin
			Nmap::Program.sudo_scan do |nmap|
				nmap.syn_scan = true
				nmap.udp_scan = true
				nmap.null_scan = true
				nmap.fin_scan = true
				nmap.xmas_scan = true
				nmap.targets = "#{arg[:single_root]}"
			end
		rescue RProgram::ProgramNotFound
			puts "#{R}[!] Need Sudo#{W}"
		end
	end
end

def make_wordlist(arg)
	if arg[:letter]
		if arg[:output]
			begin
				a = "#{arg[:letter]}".chars.permutation.map &:join
				File.open("#{arg[:output]}", 'w') do |f| 
					a.each do |result|
						f.puts result
					end
				end
			rescue
			end
		end
	end
end
def admin_pages_finder(arg)
	if arg[:admin_page_finder]
		banners
		count = 0
		find = "http://#{arg[:admin_page_finder]}/"
		fh = File.open("paths.txt","r")
		k = fh.readlines
		k.each do |lines|
			url = URI.parse(URI.encode(find.strip)+lines.strip)
			req = Net::HTTP::Get.new(url.to_s)
			res = Net::HTTP.start(url.hostname, url.port) {|run|
				sleep(0.1)
				puts "\n#{O} Try [#{count += 1}] : #{url}#{W}"
				run.request(req)
			}
			if res.code == "404"
				puts"#{R}[-] 404 Not Found#{W}"
			elsif res.code == "200"
				puts"#{G}[+] 200 Admin Page Found#{W}"
			elsif res.code == "302"
				puts"#{C}[!] 302 Found#{W}"
			else
				puts"#{B}[!]#{res.code} Found#{W}"
			end
		end
	end
end
if __FILE__ == $0
	if ARGV.empty?
		puts "Need help? Try ./#{__FILE__} -h or --help"
		exit
	end
	begin
		arg = arguments
		single_full_tcp(arg)
		file_tcp_scan(arg)
		make_wordlist(arg)
		scan_firewall_vulnerabilities(arg)
		admin_pages_finder(arg)
		example(arg)
		puts "#{W}"
	rescue Interrupt
		puts "#{W}"
	end
end