/*
 * Copyright (C) 2008-2013 The QXmpp developers
 *
 * Authors:
 *  Manjeet Dahiya
 *  Jeremy Lainé
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

#ifndef QXMPPSASL_H
#define QXMPPSASL_H

#include <QByteArray>

#include "QXmppConfiguration.h"
#include "QXmppGlobal.h"
#include "QXmppLogger.h"

class QXmppSaslClientPrivate;

class QXmppSaslClient;
typedef QXmppSaslClient *(*QXmppSaslClientFactory)(QObject *);

class QXMPP_EXPORT QXmppSaslClient : public QXmppLoggable
{
public:
    QXmppSaslClient(QObject *parent = 0);
    virtual ~QXmppSaslClient();

    virtual QString mechanism() const = 0;
    virtual void configure(const QXmppConfiguration &conf);
    virtual bool respond(const QByteArray &challenge, QByteArray &response) = 0;

    static QStringList availableMechanisms();
    static void addMechanism(const QString &mechanism, QXmppSaslClientFactory factory);
    static void removeMechanism(const QString &mechanism);
    static QXmppSaslClient* create(const QString &mechanism, QObject *parent = 0);

private:
    QXmppSaslClientPrivate *d;
};

#endif
