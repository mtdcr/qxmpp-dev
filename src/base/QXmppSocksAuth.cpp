/*
 * Copyright (C) 2012 The QXmpp developers
 *
 * Author:
 *  Andreas Oberritter
 *
 * Source:
 *  http://code.google.com/p/qxmpp
 *
 * This file is a part of QXmpp library.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 */

#include "QXmppSocksAuth.h"

QXmppSocksAuthMethod::QXmppSocksAuthMethod()
{
    reset();
}

void QXmppSocksAuthMethod::reset()
{
    m_state = AuthContinue;
}

enum QXmppSocksAuthMethod::State QXmppSocksAuthMethod::state() const
{
    return m_state;
}

void QXmppSocksAuthMethod::setState(enum State state)
{
    m_state = state;
}

enum QXmppSocksAuthMethod::State QXmppSocksAuthMethodNone::state() const
{
    return AuthOk;
}

enum QXmppSocksAuthMethod::Type QXmppSocksAuthMethodNone::type() const
{
    return None;
}

void QXmppSocksAuthMethodNone::stepRead(const QByteArray &buffer)
{
    Q_UNUSED(buffer)
}

QByteArray QXmppSocksAuthMethodNone::stepWrite()
{
    return QByteArray();
}

enum QXmppSocksAuthMethod::Type QXmppSocksAuthMethodUserPass::type() const
{
    return QXmppSocksAuthMethod::UserPass;
}

void QXmppSocksAuthMethodUserPass::stepRead(const QByteArray &buffer)
{
    if (buffer.size() == 2 && buffer.at(0) == Version && buffer.at(1) == 0x00)
        setState(AuthOk);
    else
        setState(AuthFail);
}

QByteArray QXmppSocksAuthMethodUserPass::stepWrite() const
{
    QByteArray buffer;

    buffer.append(Version);           // VER
    buffer.append(m_username.size()); // ULEN
    buffer.append(m_username);        // UNAME
    buffer.append(m_password.size()); // PLEN
    buffer.append(m_password);        // PASSWD

    return buffer;
}

const QString &QXmppSocksAuthMethodUserPass::username() const
{
    return m_username;
}

bool QXmppSocksAuthMethodUserPass::setUsername(const QString &username)
{
    if (username.size() > 255)
        return false;
    m_username = username;
    return true;
}

const QString &QXmppSocksAuthMethodUserPass::password() const
{
    return m_password;
}

bool QXmppSocksAuthMethodUserPass::setPassword(const QString &password)
{
    if (password.size() > 255)
        return false;
    m_password = password;
    return true;
}
