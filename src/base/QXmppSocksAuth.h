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

#ifndef QXMPPSOCKSAUTH_H
#define QXMPPSOCKSAUTH_H

#include "QXmppGlobal.h"

class QXMPP_EXPORT QXmppSocksAuthMethod
{
public:
    enum State {
        AuthOk,
        AuthFail,
        AuthContinue,
    };

    enum Type {
        None = 0,
        GSSAPI = 1,
        UserPass = 2,
        CHAP = 3,
        CRAM = 5,
        SSL = 6,
        NDS = 7,
        MAF = 8,
    };

    QXmppSocksAuthMethod();
    virtual void reset();
    virtual enum State state() const;

    virtual enum Type type() const = 0;
    virtual void stepRead(const QByteArray &buffer) = 0;
    virtual QByteArray stepWrite() = 0;

private:
    enum State m_state;

protected:
    void setState(enum State state);
};

class QXMPP_EXPORT QXmppSocksAuthMethodNone : public QXmppSocksAuthMethod
{
public:
    virtual enum State state() const;
    virtual enum Type type() const;
    virtual void stepRead(const QByteArray &buffer);
    virtual QByteArray stepWrite();
};

class QXMPP_EXPORT QXmppSocksAuthMethodUserPass : public QXmppSocksAuthMethod
{
    QString m_username;
    QString m_password;
    static const int Version = 0x01;

public:
    virtual enum Type type() const;
    virtual void stepRead(const QByteArray &buffer);
    virtual QByteArray stepWrite() const;

    const QString &username() const;
    bool setUsername(const QString &username);
    const QString &password() const;
    bool setPassword(const QString &password);
};

#endif
