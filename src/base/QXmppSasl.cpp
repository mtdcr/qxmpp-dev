/*
 * Copyright (C) 2008-2013 The QXmpp developers
 *
 * Authors:
 *  Manjeet Dahiya
 *  Jeremy Lainé
 *  Andreas Oberritter
 *
 * Source:
 *  https://github.com/qxmpp-project/qxmpp
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

#include <cstdlib>

#include <QCryptographicHash>
#include <QDomElement>
#include <QHash>
#include <QStringList>
#if QT_VERSION >= 0x050000
#include <QUrlQuery>
#else
#include <QUrl>
#endif

#include "QXmppSasl_p.h"
#include "QXmppUtils.h"

const char *ns_xmpp_sasl = "urn:ietf:params:xml:ns:xmpp-sasl";

static QByteArray forcedNonce;

// Calculate digest response for use with XMPP/SASL.

static QByteArray calculateDigest(const QByteArray &method, const QByteArray &digestUri, const QByteArray &secret, const QByteArray &nonce, const QByteArray &cnonce, const QByteArray &nc)
{
    const QByteArray A1 = secret + ':' + nonce + ':' + cnonce;
    const QByteArray A2 = method + ':' + digestUri;

    QByteArray HA1 = QCryptographicHash::hash(A1, QCryptographicHash::Md5).toHex();
    QByteArray HA2 = QCryptographicHash::hash(A2, QCryptographicHash::Md5).toHex();
    const QByteArray KD = HA1 + ':' + nonce + ':' + nc + ':' + cnonce + ":auth:" + HA2;
    return QCryptographicHash::hash(KD, QCryptographicHash::Md5).toHex();
}

static QByteArray generateNonce()
{
    if (!forcedNonce.isEmpty())
        return forcedNonce;

    QByteArray nonce = QXmppUtils::generateRandomBytes(32);

    // The random data can the '=' char is not valid as it is a delimiter,
    // so to be safe, base64 the nonce
    return nonce.toBase64();
}

QXmppSaslAuth::QXmppSaslAuth(const QString &mechanism, const QByteArray &value)
    : m_mechanism(mechanism)
    , m_value(value)
{
}

QString QXmppSaslAuth::mechanism() const
{
    return m_mechanism;
}

void QXmppSaslAuth::setMechanism(const QString &mechanism)
{
    m_mechanism = mechanism;
}

QByteArray QXmppSaslAuth::value() const
{
    return m_value;
}

void QXmppSaslAuth::setValue(const QByteArray &value)
{
    m_value = value;
}

void QXmppSaslAuth::parse(const QDomElement &element)
{
    m_mechanism = element.attribute("mechanism");
    m_value = QByteArray::fromBase64(element.text().toLatin1());
}

void QXmppSaslAuth::toXml(QXmlStreamWriter *writer) const
{
    writer->writeStartElement("auth");
    writer->writeAttribute("xmlns", ns_xmpp_sasl);
    writer->writeAttribute("mechanism", m_mechanism);
    if (!m_value.isEmpty())
        writer->writeCharacters(m_value.toBase64());
    writer->writeEndElement();
}

QXmppSaslChallenge::QXmppSaslChallenge(const QByteArray &value)
    : m_value(value)
{
}

QByteArray QXmppSaslChallenge::value() const
{
    return m_value;
}

void QXmppSaslChallenge::setValue(const QByteArray &value)
{
    m_value = value;
}

void QXmppSaslChallenge::parse(const QDomElement &element)
{
    m_value = QByteArray::fromBase64(element.text().toLatin1());
}

void QXmppSaslChallenge::toXml(QXmlStreamWriter *writer) const
{
    writer->writeStartElement("challenge");
    writer->writeAttribute("xmlns", ns_xmpp_sasl);
    if (!m_value.isEmpty())
        writer->writeCharacters(m_value.toBase64());
    writer->writeEndElement();
}

QXmppSaslFailure::QXmppSaslFailure(const QString &condition)
    : m_condition(condition)
{
}

QString QXmppSaslFailure::condition() const
{
    return m_condition;
}

void QXmppSaslFailure::setCondition(const QString &condition)
{
    m_condition = condition;
}

void QXmppSaslFailure::parse(const QDomElement &element)
{
    m_condition = element.firstChildElement().tagName();
}

void QXmppSaslFailure::toXml(QXmlStreamWriter *writer) const
{
    writer->writeStartElement("failure");
    writer->writeAttribute("xmlns", ns_xmpp_sasl);
    if (!m_condition.isEmpty())
        writer->writeEmptyElement(m_condition);
    writer->writeEndElement();
}

QXmppSaslResponse::QXmppSaslResponse(const QByteArray &value)
    : m_value(value)
{
}

QByteArray QXmppSaslResponse::value() const
{
    return m_value;
}

void QXmppSaslResponse::setValue(const QByteArray &value)
{
    m_value = value;
}

void QXmppSaslResponse::parse(const QDomElement &element)
{
    m_value = QByteArray::fromBase64(element.text().toLatin1());
}

void QXmppSaslResponse::toXml(QXmlStreamWriter *writer) const
{
    writer->writeStartElement("response");
    writer->writeAttribute("xmlns", ns_xmpp_sasl);
    if (!m_value.isEmpty())
        writer->writeCharacters(m_value.toBase64());
    writer->writeEndElement();
}

QXmppSaslSuccess::QXmppSaslSuccess()
{
}

void QXmppSaslSuccess::parse(const QDomElement &element)
{
    Q_UNUSED(element);
}

void QXmppSaslSuccess::toXml(QXmlStreamWriter *writer) const
{
    writer->writeStartElement("success");
    writer->writeAttribute("xmlns", ns_xmpp_sasl);
    writer->writeEndElement();
}

class QXmppSaslClientPrivate
{
public:
    QString host;
    QString serviceType;
    QString username;
    QString password;

    static QHash<QString, QXmppSaslClientFactory> mechanisms;
private:
    static QHash<QString, QXmppSaslClientFactory> builtinMechanisms();
};

/// Initializes the list of mechanisms supported out-of-the-box.

QHash<QString, QXmppSaslClientFactory> QXmppSaslClientPrivate::builtinMechanisms()
{
    QHash<QString, QXmppSaslClientFactory> m;

    m.insert("PLAIN", QXmppSaslClientPlain::create);
    m.insert("DIGEST-MD5", QXmppSaslClientDigestMd5::create);
    m.insert("ANONYMOUS", QXmppSaslClientAnonymous::create);
    m.insert("X-FACEBOOK-PLATFORM", QXmppSaslClientFacebook::create);
    m.insert("X-MESSENGER-OAUTH2", QXmppSaslClientWindowsLive::create);
    m.insert("X-OAUTH2", QXmppSaslClientGoogle::create);

    return m;
}

/// Set of known mechanisms.

QHash<QString, QXmppSaslClientFactory> QXmppSaslClientPrivate::mechanisms = builtinMechanisms();

QXmppSaslClient::QXmppSaslClient(QObject *parent)
    : QXmppLoggable(parent)
    , d(new QXmppSaslClientPrivate)
{
}

QXmppSaslClient::~QXmppSaslClient()
{
    delete d;
}

/// Adds a new mechanism.

void QXmppSaslClient::addMechanism(const QString &mechanism, QXmppSaslClientFactory factory)
{
    QXmppSaslClientPrivate::mechanisms.insert(mechanism, factory);
}

/// Removes an existing mechanism.

void QXmppSaslClient::removeMechanism(const QString &mechanism)
{
    QXmppSaslClientPrivate::mechanisms.remove(mechanism);
}

/// Returns a list of supported mechanisms.

QStringList QXmppSaslClient::availableMechanisms()
{
    return QXmppSaslClientPrivate::mechanisms.keys();
}

/// Creates an SASL client for the given mechanism.

QXmppSaslClient* QXmppSaslClient::create(const QString &mechanism, QObject *parent)
{
    QHash<QString, QXmppSaslClientFactory>::iterator i(QXmppSaslClientPrivate::mechanisms.find(mechanism));
    if (i != QXmppSaslClientPrivate::mechanisms.end())
        return i.value()(parent);
    return 0;
}

void QXmppSaslClient::configure(const QXmppConfiguration &conf)
{
    Q_UNUSED(conf);
}

QXmppSaslClientAnonymous::QXmppSaslClientAnonymous(QObject *parent)
    : QXmppSaslClient(parent)
    , m_step(0)
{
}

QXmppSaslClient *QXmppSaslClientAnonymous::create(QObject *parent)
{
    return new QXmppSaslClientAnonymous(parent);
}

QString QXmppSaslClientAnonymous::mechanism() const
{
    return "ANONYMOUS";
}

bool QXmppSaslClientAnonymous::respond(const QByteArray &challenge, QByteArray &response)
{
    Q_UNUSED(challenge);
    if (m_step == 0) {
        response = QByteArray();
        m_step++;
        return true;
    } else {
        warning("QXmppSaslClientAnonymous : Invalid step");
        return false;
    }
}

QXmppSaslClientDigestMd5::QXmppSaslClientDigestMd5(QObject *parent)
    : QXmppSaslClient(parent)
    , m_nc("00000001")
    , m_step(0)
{
    m_cnonce = generateNonce();
}

QXmppSaslClient *QXmppSaslClientDigestMd5::create(QObject *parent)
{
    return new QXmppSaslClientDigestMd5(parent);
}

QString QXmppSaslClientDigestMd5::mechanism() const
{
    return "DIGEST-MD5";
}

void QXmppSaslClientDigestMd5::configure(const QXmppConfiguration &conf)
{
    m_host = conf.domain();
    m_serviceType = QLatin1String("xmpp");
    m_username = conf.user();
    m_password = conf.password();
}

bool QXmppSaslClientDigestMd5::respond(const QByteArray &challenge, QByteArray &response)
{
    Q_UNUSED(challenge);
    const QByteArray digestUri = QString("%1/%2").arg(m_serviceType, m_host).toUtf8();

    if (m_step == 0) {
        response = QByteArray();
        m_step++;
        return true;
    } else if (m_step == 1) {
        const QMap<QByteArray, QByteArray> input = QXmppSaslDigestMd5::parseMessage(challenge);

        if (!input.contains("nonce")) {
            warning("QXmppSaslClientDigestMd5 : Invalid input on step 1");
            return false;
        }

        // determine realm
        const QByteArray realm = input.value("realm");

        // determine quality of protection
        const QList<QByteArray> qops = input.value("qop", "auth").split(',');
        if (!qops.contains("auth")) {
            warning("QXmppSaslClientDigestMd5 : Invalid quality of protection");
            return false;
        }

        m_nonce = input.value("nonce");
        m_secret = QCryptographicHash::hash(
            m_username.toUtf8() + ":" + realm + ":" + m_password.toUtf8(),
            QCryptographicHash::Md5);

        // Build response
        QMap<QByteArray, QByteArray> output;
        output["username"] = m_username.toUtf8();
        if (!realm.isEmpty())
            output["realm"] = realm;
        output["nonce"] = m_nonce;
        output["qop"] = "auth";
        output["cnonce"] = m_cnonce;
        output["nc"] = m_nc;
        output["digest-uri"] = digestUri;
        output["response"] = calculateDigest("AUTHENTICATE", digestUri, m_secret, m_nonce, m_cnonce, m_nc);
        output["charset"] = "utf-8";

        response = QXmppSaslDigestMd5::serializeMessage(output);
        m_step++;
        return true;
    } else if (m_step == 2) {
        const QMap<QByteArray, QByteArray> input = QXmppSaslDigestMd5::parseMessage(challenge);

        // check new challenge
        if (input.value("rspauth") != calculateDigest(QByteArray(), digestUri, m_secret, m_nonce, m_cnonce, m_nc)) {
            warning("QXmppSaslClientDigestMd5 : Invalid challenge on step 2");
            return false;
        }

        response = QByteArray();
        m_step++;
        return true;
    } else {
        warning("QXmppSaslClientDigestMd5 : Invalid step");
        return false;
    }
}

QXmppSaslClientFacebook::QXmppSaslClientFacebook(QObject *parent)
    : QXmppSaslClient(parent)
    , m_step(0)
{
}

QXmppSaslClient *QXmppSaslClientFacebook::create(QObject *parent)
{
    return new QXmppSaslClientFacebook(parent);
}

QString QXmppSaslClientFacebook::mechanism() const
{
    return "X-FACEBOOK-PLATFORM";
}

void QXmppSaslClientFacebook::configure(const QXmppConfiguration &conf)
{
    m_accessToken = conf.facebookAccessToken();
    m_apiKey = conf.facebookAppId();
}

bool QXmppSaslClientFacebook::respond(const QByteArray &challenge, QByteArray &response)
{
    if (m_step == 0) {
        // no initial response
        response = QByteArray();
        m_step++;
        return true;
    } else if (m_step == 1) {
        // parse request
#if QT_VERSION >= 0x050000
        QUrlQuery requestUrl(challenge);
#else
        QUrl requestUrl;
        requestUrl.setEncodedQuery(challenge);
#endif
        if (!requestUrl.hasQueryItem("method") || !requestUrl.hasQueryItem("nonce")) {
            warning("QXmppSaslClientFacebook : Invalid challenge, nonce or method missing");
            return false;
        }

        // build response
#if QT_VERSION >= 0x050000
        QUrlQuery responseUrl;
#else
        QUrl responseUrl;
#endif
        responseUrl.addQueryItem("access_token", m_accessToken);
        responseUrl.addQueryItem("api_key", m_apiKey);
        responseUrl.addQueryItem("call_id", QLatin1String(""));
        responseUrl.addQueryItem("method", requestUrl.queryItemValue("method"));
        responseUrl.addQueryItem("nonce", requestUrl.queryItemValue("nonce"));
        responseUrl.addQueryItem("v", "1.0");

#if QT_VERSION >= 0x050000
        response = responseUrl.query().toUtf8();
#else
        response = responseUrl.encodedQuery();
#endif
        m_step++;
        return true;
    } else {
        warning("QXmppSaslClientFacebook : Invalid step");
        return false;
    }
}

QXmppSaslClientGoogle::QXmppSaslClientGoogle(QObject *parent)
    : QXmppSaslClient(parent)
    , m_step(0)
{
}

QXmppSaslClient *QXmppSaslClientGoogle::create(QObject *parent)
{
    return new QXmppSaslClientGoogle(parent);
}

QString QXmppSaslClientGoogle::mechanism() const
{
    return "X-OAUTH2";
}

void QXmppSaslClientGoogle::configure(const QXmppConfiguration &conf)
{
    m_username = conf.user();
    m_accessToken = conf.googleAccessToken();
}

bool QXmppSaslClientGoogle::respond(const QByteArray &challenge, QByteArray &response)
{
    Q_UNUSED(challenge);
    if (m_step == 0) {
        // send initial response
        response = QString('\0' + m_username + '\0' + m_accessToken).toUtf8();
        m_step++;
        return true;
    } else {
        warning("QXmppSaslClientGoogle : Invalid step");
        return false;
    }
}

QXmppSaslClientPlain::QXmppSaslClientPlain(QObject *parent)
    : QXmppSaslClient(parent)
    , m_step(0)
{
}

QXmppSaslClient *QXmppSaslClientPlain::create(QObject *parent)
{
    return new QXmppSaslClientPlain(parent);
}

QString QXmppSaslClientPlain::mechanism() const
{
    return "PLAIN";
}

void QXmppSaslClientPlain::configure(const QXmppConfiguration &conf)
{
    m_username = conf.user();
    m_password = conf.password();
}

bool QXmppSaslClientPlain::respond(const QByteArray &challenge, QByteArray &response)
{
    Q_UNUSED(challenge);
    if (m_step == 0) {
        response = QString('\0' + m_username + '\0' + m_password).toUtf8();
        m_step++;
        return true;
    } else {
        warning("QXmppSaslClientPlain : Invalid step");
        return false;
    }
}

QXmppSaslClientWindowsLive::QXmppSaslClientWindowsLive(QObject *parent)
    : QXmppSaslClient(parent)
    , m_step(0)
{
}

QXmppSaslClient *QXmppSaslClientWindowsLive::create(QObject *parent)
{
    return new QXmppSaslClientWindowsLive(parent);
}

QString QXmppSaslClientWindowsLive::mechanism() const
{
    return "X-MESSENGER-OAUTH2";
}

void QXmppSaslClientWindowsLive::configure(const QXmppConfiguration &conf)
{
    m_accessToken = conf.windowsLiveAccessToken();
}

bool QXmppSaslClientWindowsLive::respond(const QByteArray &challenge, QByteArray &response)
{
    Q_UNUSED(challenge);
    if (m_step == 0) {
        // send initial response
        response = QByteArray::fromBase64(m_accessToken.toLatin1());
        m_step++;
        return true;
    } else {
        warning("QXmppSaslClientWindowsLive : Invalid step");
        return false;
    }
}

class QXmppSaslServerPrivate
{
public:
    QString username;
    QString password;
    QByteArray passwordDigest;
    QString realm;
};

QXmppSaslServer::QXmppSaslServer(QObject *parent)
    : QXmppLoggable(parent)
    , d(new QXmppSaslServerPrivate)
{
}

QXmppSaslServer::~QXmppSaslServer()
{
    delete d;
}

/// Creates an SASL server for the given mechanism.

QXmppSaslServer* QXmppSaslServer::create(const QString &mechanism, QObject *parent)
{
    if (mechanism == "PLAIN") {
        return new QXmppSaslServerPlain(parent);
    } else if (mechanism == "DIGEST-MD5") {
        return new QXmppSaslServerDigestMd5(parent);
    } else if (mechanism == "ANONYMOUS") {
        return new QXmppSaslServerAnonymous(parent);
    } else {
        return 0;
    }
}

/// Returns the username.

QString QXmppSaslServer::username() const
{
    return d->username;
}

/// Sets the username.

void QXmppSaslServer::setUsername(const QString &username)
{
    d->username = username;
}

/// Returns the password.

QString QXmppSaslServer::password() const
{
    return d->password;
}

/// Sets the password.

void QXmppSaslServer::setPassword(const QString &password)
{
    d->password = password;
}

/// Returns the password digest.

QByteArray QXmppSaslServer::passwordDigest() const
{
    return d->passwordDigest;
}

/// Sets the password digest.

void QXmppSaslServer::setPasswordDigest(const QByteArray &digest)
{
    d->passwordDigest = digest;
}

/// Returns the realm.

QString QXmppSaslServer::realm() const
{
    return d->realm;
}

/// Sets the realm.

void QXmppSaslServer::setRealm(const QString &realm)
{
    d->realm = realm;
}

QXmppSaslServerAnonymous::QXmppSaslServerAnonymous(QObject *parent)
    : QXmppSaslServer(parent)
    , m_step(0)
{
}

QString QXmppSaslServerAnonymous::mechanism() const
{
    return "ANONYMOUS";
}

QXmppSaslServer::Response QXmppSaslServerAnonymous::respond(const QByteArray &request, QByteArray &response)
{
    Q_UNUSED(request);
    if (m_step == 0) {
        m_step++;
        response = QByteArray();
        return Succeeded;
    } else {
        warning("QXmppSaslServerAnonymous : Invalid step");
        return Failed;
    }
}

QXmppSaslServerDigestMd5::QXmppSaslServerDigestMd5(QObject *parent)
    : QXmppSaslServer(parent)
    , m_step(0)
{
    m_nonce = generateNonce();
}

QString QXmppSaslServerDigestMd5::mechanism() const
{
    return "DIGEST-MD5";
}

QXmppSaslServer::Response QXmppSaslServerDigestMd5::respond(const QByteArray &request, QByteArray &response)
{
    if (m_step == 0) {
        QMap<QByteArray, QByteArray> output;
        output["nonce"] = m_nonce;
        if (!realm().isEmpty())
            output["realm"] = realm().toUtf8();
        output["qop"] = "auth";
        output["charset"] = "utf-8";
        output["algorithm"] = "md5-sess";

        m_step++;
        response = QXmppSaslDigestMd5::serializeMessage(output);
        return Challenge;
    } else if (m_step == 1) {
        const QMap<QByteArray, QByteArray> input = QXmppSaslDigestMd5::parseMessage(request);
        const QByteArray realm = input.value("realm");
        const QByteArray digestUri = input.value("digest-uri");

        if (input.value("qop") != "auth") {
            warning("QXmppSaslServerDigestMd5 : Invalid quality of protection");
            return Failed;
        }

        setUsername(QString::fromUtf8(input.value("username")));
        if (password().isEmpty() && passwordDigest().isEmpty())
            return InputNeeded;

        m_nc = input.value("nc");
        m_cnonce = input.value("cnonce");
        if (!password().isEmpty()) {
            m_secret = QCryptographicHash::hash(
                username().toUtf8() + ":" + realm + ":" + password().toUtf8(),
                QCryptographicHash::Md5);
        } else {
            m_secret = passwordDigest();
        }

        if (input.value("response") != calculateDigest("AUTHENTICATE", digestUri, m_secret, m_nonce, m_cnonce, m_nc))
            return Failed;

        QMap<QByteArray, QByteArray> output;
        output["rspauth"] = calculateDigest(QByteArray(), digestUri, m_secret, m_nonce, m_cnonce, m_nc);

        m_step++;
        response = QXmppSaslDigestMd5::serializeMessage(output);
        return Challenge;
    } else if (m_step == 2) {
        m_step++;
        response = QByteArray();
        return Succeeded;
    } else {
        warning("QXmppSaslServerDigestMd5 : Invalid step");
        return Failed;
    }
}

QXmppSaslServerPlain::QXmppSaslServerPlain(QObject *parent)
    : QXmppSaslServer(parent)
    , m_step(0)
{
}

QString QXmppSaslServerPlain::mechanism() const
{
    return "PLAIN";
}

QXmppSaslServer::Response QXmppSaslServerPlain::respond(const QByteArray &request, QByteArray &response)
{
    if (m_step == 0) {
        if (request.isEmpty()) {
            response = QByteArray();
            return Challenge;
        }

        QList<QByteArray> auth = request.split('\0');
        if (auth.size() != 3) {
            warning("QXmppSaslServerPlain : Invalid input");
            return Failed;
        }
        setUsername(QString::fromUtf8(auth[1]));
        setPassword(QString::fromUtf8(auth[2]));

        m_step++;
        response = QByteArray();
        return InputNeeded;
    } else {
        warning("QXmppSaslServerPlain : Invalid step");
        return Failed;
    }
}

void QXmppSaslDigestMd5::setNonce(const QByteArray &nonce)
{
    forcedNonce = nonce;
}

QMap<QByteArray, QByteArray> QXmppSaslDigestMd5::parseMessage(const QByteArray &ba)
{
    QMap<QByteArray, QByteArray> map;
    int startIndex = 0;
    int pos = 0;
    while ((pos = ba.indexOf("=", startIndex)) >= 0)
    {
        // key get name and skip equals
        const QByteArray key = ba.mid(startIndex, pos - startIndex).trimmed();
        pos++;

        // check whether string is quoted
        if (ba.at(pos) == '"')
        {
            // skip opening quote
            pos++;
            int endPos = ba.indexOf('"', pos);
            // skip quoted quotes
            while (endPos >= 0 && ba.at(endPos - 1) == '\\')
                endPos = ba.indexOf('"', endPos + 1);
            if (endPos < 0)
            {
                qWarning("Unfinished quoted string");
                return map;
            }
            // unquote
            QByteArray value = ba.mid(pos, endPos - pos);
            value.replace("\\\"", "\"");
            value.replace("\\\\", "\\");
            map[key] = value;
            // skip closing quote and comma
            startIndex = endPos + 2;
        } else {
            // non-quoted string
            int endPos = ba.indexOf(',', pos);
            if (endPos < 0)
                endPos = ba.size();
            map[key] = ba.mid(pos, endPos - pos);
            // skip comma
            startIndex = endPos + 1;
        }
    }
    return map;
}

QByteArray QXmppSaslDigestMd5::serializeMessage(const QMap<QByteArray, QByteArray> &map)
{
    QByteArray ba;
    foreach (const QByteArray &key, map.keys())
    {
        if (!ba.isEmpty())
            ba.append(',');
        ba.append(key + "=");
        QByteArray value = map[key];
        const char *separators = "()<>@,;:\\\"/[]?={} \t";
        bool quote = false;
        for (const char *c = separators; *c; c++)
        {
            if (value.contains(*c))
            {
                quote = true;
                break;
            }
        }
        if (quote)
        {
            value.replace("\\", "\\\\");
            value.replace("\"", "\\\"");
            ba.append("\"" + value + "\"");
        }
        else
            ba.append(value);
    }
    return ba;
}
