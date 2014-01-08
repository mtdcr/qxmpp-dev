/*
 * Copyright (C) 2008-2012 The QXmpp developers
 *
 * Author:
 *  Jeremy Lainé
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

#include <QDataStream>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>

#include "QXmppSocks.h"

const static char SocksVersion = 5;

enum Command {
    ConnectCommand = 1,
    BindCommand = 2,
    AssociateCommand = 3,
};

enum AddressType {
    IPv4Address = 1,
    DomainName = 3,
    IPv6Address = 4,
};

enum ReplyType {
    Succeeded = 0,
    SocksFailure = 1,
    ConnectionNotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
};

enum State {
    ConnectState = 0,
    AuthState = 1,
    CommandState = 2,
    ReadyState = 3,
};

static QByteArray encodeHostAndPort(quint8 type, const QByteArray &host, quint16 port)
{
    QByteArray buffer;
    QDataStream stream(&buffer, QIODevice::WriteOnly);
    // set host name
    quint8 hostLength = host.size();
    stream << type;
    stream << hostLength;
    stream.writeRawData(host.constData(), hostLength);
    // set port
    stream << port;
    return buffer;
}

static bool parseHostAndPort(const QByteArray buffer, quint8 &type, QByteArray &host, quint16 &port)
{
    if (buffer.size() < 4)
        return false;

    QDataStream stream(buffer);
    // get host name
    quint8 hostLength;
    stream >> type;
    stream >> hostLength;
    if (buffer.size() < hostLength + 4)
    {
        qWarning("Invalid host length");
        return false;
    }
    host.resize(hostLength);
    stream.readRawData(host.data(), hostLength);
    // get port
    stream >> port;
    return true;
}

QXmppSocksClient::QXmppSocksClient(const QString &proxyHost, quint16 proxyPort, QObject *parent)
    : QTcpSocket(parent),
    m_authMethod(QXmppSocksAuthMethod::None),
    m_proxyHost(proxyHost),
    m_proxyPort(proxyPort),
    m_step(ConnectState)
{
    connect(this, SIGNAL(connected()), this, SLOT(slotConnected()));
    connect(this, SIGNAL(readyRead()), this, SLOT(slotReadyRead()));
}

void QXmppSocksClient::clearAuthMethods()
{
    m_authMethods.clear();
}

bool QXmppSocksClient::addAuthMethod(QXmppSocksAuthMethod *authMethod)
{
    if (authMethod->type() < 0x00 || authMethod->type() > 0xFE || m_authMethods.size() >= 255)
        return false;

    m_authMethods[authMethod->type()] = authMethod;
    return true;
}

void QXmppSocksClient::connectToHost(const QString &hostName, quint16 hostPort)
{
    m_hostName = hostName;
    m_hostPort = hostPort;
    QTcpSocket::connectToHost(m_proxyHost, m_proxyPort);
}

void QXmppSocksClient::slotConnected()
{
    m_step = ConnectState;

    // disconnect from signal
    disconnect(this, SIGNAL(connected()), this, SLOT(slotConnected()));

    // send connect to server
    QByteArray buffer;
    buffer.resize(2);
    buffer[0] = SocksVersion;
    int nmethods = m_authMethods.size();
    if (nmethods > 0) {
        buffer[1] = m_authMethods.size();
        QHash<enum QXmppSocksAuthMethod::Type, QXmppSocksAuthMethod *>::const_iterator it(m_authMethods.constBegin());
        while (it != m_authMethods.constEnd()) {
            buffer.append(it.key());
            ++it;
        }
    } else {
        buffer[1] = 0x01; // number of methods
        buffer.append(QXmppSocksAuthMethod::None);
    }
    write(buffer);
}

QByteArray QXmppSocksClient::connectCommand()
{
    QByteArray buffer;

    buffer.resize(3);
    buffer[0] = SocksVersion;
    buffer[1] = ConnectCommand;
    buffer[2] = 0x00; // reserved
    buffer.append(encodeHostAndPort(
        DomainName,
        m_hostName.toLatin1(),
        m_hostPort));

    return buffer;
}

void QXmppSocksClient::slotReadyRead()
{
    if (m_step == ConnectState)
    {
        // receive connect to server response
        QByteArray buffer = readAll();
        if (buffer.size() != 2 || buffer.at(0) != SocksVersion)
        {
            qWarning("QXmppSocksClient received an invalid response during handshake");
            close();
            return;
        }

        m_authMethod = (QXmppSocksAuthMethod::Type)buffer.at(1);
        if (m_authMethod == QXmppSocksAuthMethod::None && (m_authMethods.size() == 0 || m_authMethods.contains(m_authMethod))) {
            write(connectCommand());
            m_step = CommandState;
        } else if (m_authMethods.contains(m_authMethod)) {
            QXmppSocksAuthMethod *m = m_authMethods[m_authMethod];
            m->reset();
            write(m->stepWrite());
            m_step = AuthState;
        } else {
            qWarning("QXmppSocksClient received an invalid auth method");
            close();
            return;
        }
    } else if (m_step == AuthState) {
        QXmppSocksAuthMethod *m = m_authMethods[m_authMethod];
        m->stepRead(readAll());
        switch (m->state()) {
        case QXmppSocksAuthMethod::AuthOk:
            write(connectCommand());
            m_step = CommandState;
            break;
        case QXmppSocksAuthMethod::AuthFail:
            qWarning("QXmppSocksClient authentication failed");
            close();
            break;
        case QXmppSocksAuthMethod::AuthContinue:
            write(m->stepWrite());
            break;
        }
    } else if (m_step == CommandState) {
        m_step = ReadyState;

        // disconnect from signal
        disconnect(this, SIGNAL(readyRead()), this, SLOT(slotReadyRead()));

        // receive CONNECT response
        QByteArray buffer = readAll();
        if (buffer.size() < 6 ||
            buffer.at(0) != SocksVersion ||
            buffer.at(1) != Succeeded ||
            buffer.at(2) != 0)
        {
            qWarning("QXmppSocksClient received an invalid response to CONNECT command");
            close();
            return;
        }

        // parse host
        quint8 hostType;
        QByteArray hostName;
        quint16 hostPort;
        if (!parseHostAndPort(buffer.mid(3), hostType, hostName, hostPort))
        {
            qWarning("QXmppSocksClient could not parse type/host/port");
            close();
            return;
        }
        // FIXME : what do we do with the resulting name / port?

        // notify of connection
        emit ready();
    }
}

QXmppSocksServer::QXmppSocksServer(QObject *parent)
    : QObject(parent)
{
    m_server = new QTcpServer(this);
    connect(m_server, SIGNAL(newConnection()), this, SLOT(slotNewConnection()));

    m_server_v6 = new QTcpServer(this);
    connect(m_server_v6, SIGNAL(newConnection()), this, SLOT(slotNewConnection()));
}

void QXmppSocksServer::close()
{
    m_server->close();
    m_server_v6->close();
}

bool QXmppSocksServer::listen(quint16 port)
{
    if (!m_server->listen(QHostAddress::Any, port))
        return false;

    // FIXME: this fails on Linux if /proc/sys/net/ipv6/bindv6only is 0
    m_server_v6->listen(QHostAddress::AnyIPv6, m_server->serverPort());
    return true;
}

quint16 QXmppSocksServer::serverPort() const
{
    return m_server->serverPort();
}

void QXmppSocksServer::slotNewConnection()
{
    QTcpServer *server = qobject_cast<QTcpServer*>(sender());
    if (!server)
        return;

    QTcpSocket *socket = server->nextPendingConnection();
    if (!socket)
        return;

    // register socket
    m_states.insert(socket, ConnectState);
    connect(socket, SIGNAL(readyRead()), this, SLOT(slotReadyRead()));
}

void QXmppSocksServer::slotReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket || !m_states.contains(socket))
        return;

    if (m_states.value(socket) == ConnectState)
    {
        m_states.insert(socket, CommandState);

        // receive connect to server request
        QByteArray buffer = socket->readAll();
        if (buffer.size() < 3 ||
            buffer.at(0) != SocksVersion ||
            buffer.at(1) + 2 != buffer.size())
        {
            qWarning("QXmppSocksServer received invalid handshake");
            socket->close();
            return;
        }

        // check authentication method
        bool foundMethod = false;
        for (int i = 2; i < buffer.size(); i++)
        {
            if (buffer.at(i) == QXmppSocksAuthMethod::None)
            {
                foundMethod = true;
                break;
            }
        }
        if (!foundMethod)
        {
            qWarning("QXmppSocksServer received bad authentication method");
            socket->close();
            return;
        }

        // send connect to server response
        buffer.resize(2);
        buffer[0] = SocksVersion;
        buffer[1] = QXmppSocksAuthMethod::None;
        socket->write(buffer);

    } else if (m_states.value(socket) == CommandState) {
        m_states.insert(socket, ReadyState);

        // disconnect from signals
        disconnect(socket, SIGNAL(readyRead()), this, SLOT(slotReadyRead()));

        // receive command
        QByteArray buffer = socket->readAll();
        if (buffer.size() < 4 ||
            buffer.at(0) != SocksVersion ||
            buffer.at(1) != ConnectCommand ||
            buffer.at(2) != 0x00)
        {
            qWarning("QXmppSocksServer received an invalid command");
            socket->close();
            return;
        }

        // parse host
        quint8 hostType;
        QByteArray hostName;
        quint16 hostPort;
        if (!parseHostAndPort(buffer.mid(3), hostType, hostName, hostPort))
        {
            qWarning("QXmppSocksServer could not parse type/host/port");
            socket->close();
            return;
        }

        // notify of connection
        emit newConnection(socket, hostName, hostPort);

        // send response
        buffer.resize(3);
        buffer[0] = SocksVersion;
        buffer[1] = Succeeded;
        buffer[2] = 0x00;
        buffer.append(encodeHostAndPort(
            DomainName,
            hostName,
            hostPort));
        socket->write(buffer);
    }
}

