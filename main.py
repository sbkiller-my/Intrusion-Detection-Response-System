# -*- coding: utf-8 -*-

import configparser
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackQueryHandler, CallbackContext
from telegram import ChatAction, InlineKeyboardButton, InlineKeyboardMarkup, Update
import subprocess, platform
import time
import logging
import select
import re
import os, signal

config = configparser.ConfigParser()
config.read('bot.ini')



def start(update, context):
    update.message.reply_text('Salam')
    context.bot.sendChatAction(chat_id=update.message.chat_id, action=ChatAction.TYPING)
    context.bot.sendMessage(chat_id=update.message.chat_id, text="Welcome to Secured Intrusion Response System")


    if update.message.from_user.id != int(config['ADMIN']['id']):
        context.bot.sendChatAction(chat_id=update.message.chat_id, action=ChatAction.TYPING)
        context.bot.sendMessage(chat_id=update.message.chat_id, text="It seems you aren't the owner of this secured bot")
        context.bot.sendChatAction(chat_id=update.message.chat_id,action=ChatAction.TYPING)


    else:
        context.bot.sendChatAction(chat_id=update.message.chat_id, action=ChatAction.TYPING)

        context.bot.sendMessage(chat_id=update.message.chat_id, text="You can use me to monitor and response to IDS threat")
        context.bot.sendChatAction(chat_id=update.message.chat_id, action=ChatAction.TYPING)

        context.bot.sendMessage(chat_id=update.message.chat_id, text="Please use /help for more guide on how to use")




def execute(update, context):

    try:
        user_id = update.message.from_user.id
        command = update.message.text
        inline = False
    except AttributeError:
        # Using inline
        user_id = update.inline_query.from_user.id
        command = update.inline_query.query
        inline = True

    if user_id == int(config['ADMIN']['id']):
        if not inline:
            context.bot.sendChatAction(chat_id=update.message.chat_id,
                               action=ChatAction.TYPING)
        output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = output.stdout.read().decode('utf-8')
        output = '`{0}`'.format(output)

        if not inline:
            context.bot.sendMessage(chat_id=update.message.chat_id,
                        text=output, parse_mode="Markdown")
            return False

        if inline:
            return output


def help(update,context):
    update.message.reply_text("Please include the slash to execute the commands")


def tostring(s):
    # initialize an empty string
    str1 = ""

    # traverse in the string
    for ele in s:
        str1 += ele

        # return string
    return str1


def block(target):
    return target

def button(update, context):


    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    query.answer()

    data = query.data
    bData = re.split('[-:]', data)
    choice = bData[0]
    ip = bData[1]
    if choice == "Block":
        block(ip)

    query.edit_message_text(text="Selected option:"+str(block(ip)))





def snort(update,context):

    try:
        user_id = update.message.from_user.id
        command = update.message.text
        inline = False
    except AttributeError:
        # Using inline
        user_id = update.inline_query.from_user.id
        command = update.inline_query.query
        inline = True

    if user_id == int(config['ADMIN']['id']):



        if not inline:
            context.bot.sendChatAction(chat_id=update.message.chat_id,
                                       action=ChatAction.TYPING)
        command ='sudo snort -c /usr/local/etc/snort/snort.lua -i enp0s8 -s 65535 -k none -l /var/log/snort/'.split()
        ps = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE)
        time.sleep(2.2)
        context.bot.sendMessage(chat_id=update.message.chat_id,
                                text="Executing..", parse_mode="Markdown")
        poll = ps.poll()
        if poll == None:
            context.bot.sendMessage(chat_id=update.message.chat_id,
                                     text="Launched successfully", parse_mode="Markdown")

            f = subprocess.Popen(['sudo','tail', '-n0',  '-f', '/var/log/snort/alert_fast.txt'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            p = select.poll()
            p.register(f.stdout)

            while True:
                out = f.stdout.readline().decode('utf-8')
                tData = re.findall(r"[^\"\\{}\][]+", out)
                tDnT = tData[0]
                tType = tData[5]
                priority = tostring(re.findall(r"\d", tData[11]))
                tCla = tData[9]
                tPro = tData[13]

                tIP = str(tData[-1]).split()
                attacker = tIP[-1]
                victim = tIP[-1]

                reformat = "\U000026A0 <b><u>INCOMING THREAT </u></b> \U000026A0\n\n<b>Date/Time</b>\n" + tDnT + "\n\n<b>Attack Type</b>\n" + tType + "\n\n<b>Classification</b>\n" + tCla + "\n\n<b>Priority</b>\n" + priority + "\n\n<b>Protocol</b>\n" + tPro + \
                           "\n\n<b>Attacker Source IP</b>\n" + attacker + "\n\n<b>Destination Victim IP</b>\n" + victim

                txtBlock = f'Block'
                txtWhite = f'Whitelist'

                keyboard = [
                    [
                        InlineKeyboardButton(txtBlock, callback_data=txtBlock+":"+attacker),
                        InlineKeyboardButton(txtWhite, callback_data=txtWhite+":"+victim),
                    ]
                ]

                reply_markup = InlineKeyboardMarkup(keyboard)

                context.bot.sendMessage(chat_id=update.message.chat_id,
                                        text=reformat, parse_mode="HTML", reply_markup=reply_markup)


        else:
            context.bot.sendMessage(chat_id=update.message.chat_id,
                                    text="Failed to launch the Snort", parse_mode="Markdown")


def forbid(update,context):
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text="The program is killed", parse_mode="Markdown")

def terminate(update,context):
    context.bot.sendMessage(chat_id=update.message.chat_id,
                            text="The program is killed", parse_mode="Markdown")
    os.kill(os.getpid(),signal.SIGSTOP)


def unknown(update,context):
    context.bot.sendMessage(chat_id=update, text="Welcome to Secured Intrusion Response System")


def main():
    updater = Updater(token=config['KEYS']['bot_api'], use_context=True)
    dp = updater.dispatcher


    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
    )

    logger = logging.getLogger(__name__)

    def error(bot, update, error):
        logger.warning('Update "%s" caused error "%s"' % (update, error))

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("snort", snort, run_async=True))
    dp.add_handler(CommandHandler("stop", terminate))
    dp.add_handler(CallbackQueryHandler(button))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, forbid))
    dp.add_handler(MessageHandler(Filters.command, unknown))
    dp.add_error_handler(error)

    updater.start_polling()
    updater.idle()


if __name__ == '__main__':
    main()
