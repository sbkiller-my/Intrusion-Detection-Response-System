# -*- coding: utf-8 -*-

import configparser
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackQueryHandler
from telegram import ChatAction, InlineKeyboardButton, InlineKeyboardMarkup
import subprocess
import time
import logging
import select
import re
import os, signal
from collections import Counter
import matplotlib.pyplot as plt
from datetime import datetime

config = configparser.ConfigParser()
config.read('bot.ini')
def start(update, context):   # /start -- show guide

    # Welcome message
    context.bot.sendMessage(chat_id=update.message.chat_id, text="Welcome to Remote Intrusion Response System")
    # Comparing  admin token
    if update.message.from_user.id != int(config['ADMIN']['id']):
        context.bot.sendChatAction(chat_id=update.message.chat_id, action=ChatAction.TYPING)
        context.bot.sendMessage(chat_id=update.message.chat_id, text="It seems you aren't the owner of this secured bot")
        context.bot.sendChatAction(chat_id=update.message.chat_id,action=ChatAction.TYPING)

    else:
        context.bot.sendChatAction(chat_id=update.message.chat_id, action=ChatAction.TYPING)
        context.bot.sendMessage(chat_id=update.message.chat_id, text="You can use me to monitor and response to threat")
        context.bot.sendChatAction(chat_id=update.message.chat_id, action=ChatAction.TYPING)

    reformat = "<b>Available Commands</b> :\n" \
               "/snort - Start the Snort\n" \
               "/check_blacklist - Show blocked IP\n" \
               "/check_whitelist - Show whitelisted IP\n" \
               "/generate - Show session Log\n" \
               "/stat - Show all time alert\n" \
               "/reload - Reload the configuration\n" \
               "/terminate - Quit RIRS"
    # Sending message in HTML
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text=reformat, parse_mode="HTML")


def tostring(s):
    # initialize an empty string
    str1 = ""

    # traverse in the string
    for ele in s:
        str1 += ele

        # return string
    return str1


def check_blacklist(update, context): # /check_blacklist  --check whitelisted IP
    # extract blacklisted IP list from generated output from command using subprocess
    command = "sudo iptables -L INPUT -n -v | awk '/Block/ {print $8}'"
    output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    cmd_out = output.communicate()[0]
    # parse listed IP to output variable
    output = cmd_out.decode('utf-8')
    # Send message
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text=output, parse_mode="Markdown")

    return False


def check_whitelist(update, context): # /check_whitelist checking whitelisted IP
    # extract whitelisted IP list from generated output from command using subprocess
    command = "sudo awk '{print $7 $13}' /usr/local/etc/snort/whitelist.lua"
    output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    cmd_out = output.communicate()[0]
    # parse listed IP to output variable
    output = cmd_out.decode('utf-8')
    # Send message
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text=output, parse_mode="Markdown")

    return False


def block(target): # /block -- blocking IP based on IP passed in parameter
    # start timestamp of blocking requests
    timeS=str(datetime.now())
    # Iptables INPUT blocking rule command
    command = 'sudo iptables -I INPUT -m comment --comment Block -s target -j DROP'.split()
    # Parse passed IP to variable
    command[9] = target
    # Block IP using subprocess
    f = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
    # Iptables FORWARD blocking rule command
    command = 'sudo iptables -I FORWARD -m comment --comment Block -s target -j DROP'.split()
    # Parse passed IP to variable
    command[9] = target
    # Block IP using subprocess
    f = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    # return timestamp
    return timeS


def unblock(update,context): # /unblock -- unblock IP specified on argument
    # Iptables INPUT blocking rule command
    command = 'sudo iptables -D INPUT -m comment --comment Block -s target -j DROP'.split()
    # Parse specified IP to variable
    command[9] = context.args[0]
    # Block IP using subprocess
    f = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
    # Iptables FORWARD blocking rule command
    command = 'sudo iptables -D FORWARD -m comment --comment Block -s target -j DROP'.split()
    # Parse specified IP to variable
    command[9] = context.args[0]
    # Iptables FORWARD blocking rule command
    f = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    # Send message of unblocked IP with timestamp
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text=str(context.args[0])+" unblocked" + "\n\n<i>Generated at:" + str(datetime.now()) + "</i>", parse_mode="HTML")


def whitelist(target,sid): # /whitelist -- whitelist passed IP
    # read whitelist
    fi_line = open('/usr/local/etc/snort/whitelist.lua', 'r').readlines()
    # write to whitelist
    write_file = open('/usr/local/etc/snort/whitelist.lua', 'w')
    for line in fi_line:
        write_file.write(line)
        # if line contain suppress, write passed IP to line
        if 'suppress = {' in line:
            write_file.write("{ gid = 1, sid = "+sid+", track = 'by_src', ip = '"+target+"' },\n")
    # Close file
    write_file.close()


def button(update, context):  # callbackquery for keyboard button
    query = update.callback_query
    query.answer()
    # parse keyboard data to variable
    data = query.data
    # split action with IP
    bData = re.split('[-:]', data)
    # parse action
    choice = bData[0]
    # parse IP
    ip = bData[1]
    sid = bData[-1]
    # conditional action
    if choice == "Block":
        timestamp = block(ip)
        query.edit_message_text(text=ip + ' has successfully been blocked at ' +timestamp + "\n\nGenerated at:" + str(datetime.now()))

    elif choice == "Whitelist":
        whitelist(ip,sid)
        query.edit_message_text(text='Whitelisted. PLease reload the configuration (/reload).')


def priority(update, context): # /sensitivity -- set showed priority alert
    # parse argument of sensitivity to user dict
    try:
        level = int(context.args[0])
        context.user_data['level'] = level
    # if no argument received, show this
    except (IndexError, ValueError):
        reformat = "<b>Please specify alert sensitivity level</b> :\n" \
                   "1 - Basic\n" \
                   "2 - Secured\n" \
                   "3 - Cautious\n" \
                   "Default sensitivity: 3"
        context.bot.sendMessage(chat_id=update.message.chat_id,
                                text=reformat, parse_mode="HTML")


def snort(update, context): # /snort --start Snort
    user_id = update.message.from_user.id
    # Comparing admin token
    if user_id == int(config['ADMIN']['id']):
        # defining global Snort process
        global snort_ps
        context.bot.sendChatAction(chat_id=update.message.chat_id,
                                       action=ChatAction.TYPING)
        # start Snort command and run using subprocess
        command ='sudo snort -c /usr/local/etc/snort/snort.lua -i enp5s0f1 -s 65535 -k none -l /var/log/snort/'.split()
        snort_ps = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE)
        # delay for 2 second to check process status
        time.sleep(2.2)
        context.bot.sendMessage(chat_id=update.message.chat_id,
                                text="Executing..", parse_mode="Markdown")
        poll = snort_ps.poll()
        # check if process is running
        if poll is None:
            context.bot.sendMessage(chat_id=update.message.chat_id,
                                    text="Launched successfully", parse_mode="Markdown")
            # on success, tail Snort log file
            f = subprocess.Popen(['sudo','tail', '-n0',  '-f', '/var/log/snort/alert_fast.txt'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            p = select.poll()
            p.register(f.stdout)
            while True:
                # keep reading Snort log file to check for any new alert
                out = f.stdout.readline().decode('utf-8')
                # split data to list
                tData = re.findall(r"[^\"\\{}\][]+", out)
                # parse data to each variable type
                tDnT = tData[0]
                tSID = tData[3]
                tType = tData[5]
                priority = tostring(re.findall(r"\d", tData[11]))
                tCla = tData[9]
                tPro = tData[13]
                SID = tSID.split(':')
                SID = SID[1]
                # parse last data as IP
                tIP = str(tData[-1]).split()
                # split to attacker and victim IP
                attacker = tIP[0]
                victim = tIP[-1]
                # split IP from port
                attackerIP = attacker.split(':')
                victimIP = victim.split(':')
                # parse attacker IP for keyboard button uses
                aIP = attackerIP[0]

                reformat = "\U000026A0 <b><u>INCOMING THREAT </u></b> \U000026A0\n\n<b>Date/Time</b>\n" + tDnT + "\n\n<b>Attack Type</b>\n" + tType + "\n\n<b>Classification</b>\n" + tCla + "\n\n<b>Priority</b>\n" + priority + "\n\n<b>Protocol</b>\n" + tPro + \
                           "\n\n<b>Attacker Source IP</b>\n" + attacker + "\n\n<b>Destination Victim IP</b>\n" + victim

                txtBlock = f'Block'
                txtWhite = f'Whitelist'

                # pass action and IP whenever keyboard button is selected
                keyboard = [
                    [
                        InlineKeyboardButton(txtBlock, callback_data=txtBlock+":"+aIP),
                        InlineKeyboardButton(txtWhite, callback_data=txtWhite+":"+aIP+":"+SID),
                    ]
                ]
                # pass keyboard to variable
                reply_markup = InlineKeyboardMarkup(keyboard)
                # set priority level to 3 on default, else use level set by admin
                if 'level' not in context.user_data:
                    level = 3
                else:
                    level = context.user_data['level']
                # shows alert based on priority level. Append keyboard button on each alert
                if level == 1:
                    if priority == "1":
                        context.bot.sendMessage(chat_id=update.message.chat_id,
                                                text=reformat + "\n\nGenerated at: "+ str(datetime.now()), parse_mode="HTML", reply_markup=reply_markup)

                elif level == 2:
                    if priority == "2" or priority == "3":
                        context.bot.sendMessage(chat_id=update.message.chat_id,
                                                text=reformat + "\n\nGenerated at: "+ str(datetime.now()) , parse_mode="HTML", reply_markup=reply_markup)

                elif level == 3:
                    if priority == "1" or priority == "2" or priority == "3":
                        context.bot.sendMessage(chat_id=update.message.chat_id,
                                                text=reformat + "\n\nGenerated at: "+str(datetime.now()), parse_mode="HTML", reply_markup=reply_markup)

        else:
            context.bot.sendMessage(chat_id=update.message.chat_id,
                                    text="Failed to launch the Snort", parse_mode="Markdown")


def reload(update, context): # /reload -- reload configuration
    # raise hang up signal to reload Snort configuration
    command = 'sudo kill -hup '+str(snort_ps.pid+1)
    command = command.split()
    subprocess.run(command)
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text="Reloaded..", parse_mode="Markdown")


def stat(update, context): # end the snort and shows the statistic graph
    ips = Counter()
    # open Snort log file and count IP based on line
    with open('/var/log/snort/alert_fast.txt', 'r') as fi:
        for line in fi:
            s = line.split()[-3]
            st = tostring(re.findall(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s))
            if s != None:
                ips[st] += 1

    reformat = "Total Unique IP address alerts: " + str(len(ips))
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text=reformat, parse_mode="Markdown")
    # plot the graph on BarChart
    w = ips
    plt.bar(w.keys(), w.values())
    plt.savefig('stat.png')

    context.bot.sendPhoto(chat_id=update.message.chat_id, photo=open('stat.png', 'rb'), caption="No. of alert based on IP")


def generate(update, context): # end the snort to show summary of snort session
    # end Snort session
    command = 'sudo kill -2 '+str(snort_ps.pid+1)
    command = command.split()
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text="Generating log", parse_mode="Markdown")

    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text="Don't forget to restart the snort", parse_mode="Markdown")

    p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=False)
    # write summary to stat file
    logfile = open('stat.txt', 'w')
    # only print after Summary Statistic was found in terminal output
    print_flag = False
    for line in snort_ps.stdout:
        if b'Summary Statistics' in line:
            print_flag = True
        if b'Snort exiting' in line:
            print_flag = False
        if print_flag:
            logfile.write(line.decode('utf-8'))
    #close file
    logfile.close()
    context.bot.sendDocument(chat_id=update.message.chat_id, document=open('stat.txt', 'rb'))


def forbid(update, context): # input exception
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text="Consider / maybe?", parse_mode="Markdown")


def terminate(update, context): # quit RIRS
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text="The program is killed", parse_mode="Markdown")
    os.kill(os.getpid(),signal.SIGSTOP)


def unknown(update, context): # input exception
    context.bot.sendMessage(chat_id=update.message.chat_id, text="Don't enter nonsense command. Please refer /start")


def main():
    # assigning token from token file
    updater = Updater(token=config['KEYS']['bot_api'], use_context=True)
    dp = updater.dispatcher
    # raise error on exception
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
    )

    logger = logging.getLogger(__name__)
    # error handler
    def error(bot, update, error):
        logger.warning('Update "%s" caused error "%s"' % (update, error))

    # Dispatcher handler
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("snort", snort, run_async=True))
    dp.add_handler(CommandHandler("stop", terminate))
    dp.add_handler(CommandHandler("check_blacklist", check_blacklist))
    dp.add_handler(CommandHandler("check_whitelist", check_whitelist))
    dp.add_handler(CommandHandler("unblock", unblock))
    dp.add_handler(CommandHandler("reload", reload))
    dp.add_handler(CommandHandler("terminate", terminate))
    dp.add_handler(CommandHandler("stat", stat))
    dp.add_handler(CommandHandler("generate", generate))
    dp.add_handler(CommandHandler("sensitivity", priority, run_async=True))
    dp.add_handler(CallbackQueryHandler(button))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, forbid))
    dp.add_handler(MessageHandler(Filters.command, unknown))
    dp.add_error_handler(error)
    # Updater polling
    updater.start_polling()
    updater.idle()


if __name__ == '__main__':
    main()
