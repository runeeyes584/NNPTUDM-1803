let crypto = require('crypto')
let fs = require('fs')
let path = require('path')
let userController = require('../controllers/users')

const privateKeyPath = path.join(__dirname, '..', 'keys', 'jwtRS256.key.pen')
const publicKeyPath = path.join(__dirname, '..', 'keys', 'jwtRS256.key.pub.pen')
const privateKey = fs.readFileSync(privateKeyPath, 'utf8')
const publicKey = fs.readFileSync(publicKeyPath, 'utf8')
const accessTokenExpiresIn = 60 * 60

function toBase64Url(input) {
    return Buffer.from(input)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
}

function fromBase64Url(input) {
    let normalized = input.replace(/-/g, '+').replace(/_/g, '/')
    while (normalized.length % 4 !== 0) {
        normalized += '='
    }
    return Buffer.from(normalized, 'base64').toString('utf8')
}

function signToken(payload) {
    let now = Math.floor(Date.now() / 1000)
    let header = {
        alg: 'RS256',
        typ: 'JWT'
    }
    let fullPayload = {
        ...payload,
        iat: now,
        exp: now + accessTokenExpiresIn
    }
    let encodedHeader = toBase64Url(JSON.stringify(header))
    let encodedPayload = toBase64Url(JSON.stringify(fullPayload))
    let signingInput = `${encodedHeader}.${encodedPayload}`
    let signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey)
    let encodedSignature = signature.toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
    return `${signingInput}.${encodedSignature}`
}

function verifyToken(token) {
    let parts = token.split('.')
    if (parts.length !== 3) {
        throw new Error('token khong hop le')
    }
    let [encodedHeader, encodedPayload, encodedSignature] = parts
    let signingInput = `${encodedHeader}.${encodedPayload}`
    let signature = Buffer.from(
        encodedSignature.replace(/-/g, '+').replace(/_/g, '/'),
        'base64'
    )
    let isValid = crypto.verify('RSA-SHA256', Buffer.from(signingInput), publicKey, signature)
    if (!isValid) {
        throw new Error('chu ky token khong hop le')
    }
    let payload = JSON.parse(fromBase64Url(encodedPayload))
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('token da het han')
    }
    return payload
}

function getBearerToken(req) {
    let authorization = req.headers.authorization || ''
    if (!authorization.startsWith('Bearer ')) {
        return null
    }
    return authorization.slice(7)
}

function sanitizeUser(user) {
    let userObject = user.toObject ? user.toObject() : user
    delete userObject.password
    return userObject
}

async function requireAuth(req, res, next) {
    try {
        let token = getBearerToken(req)
        if (!token) {
            return res.status(401).send({
                message: 'ban chua dang nhap'
            })
        }
        let payload = verifyToken(token)
        let user = await userController.GetAnUserById(payload.sub)
        if (!user) {
            return res.status(401).send({
                message: 'nguoi dung khong ton tai'
            })
        }
        req.user = user
        req.auth = payload
        next()
    } catch (error) {
        res.status(401).send({
            message: error.message
        })
    }
}

module.exports = {
    accessTokenExpiresIn,
    signToken,
    verifyToken,
    requireAuth,
    sanitizeUser
}
