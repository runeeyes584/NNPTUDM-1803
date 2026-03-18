let express = require('express');
let router = express.Router()
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let { ChangePasswordValidator, validatedResult } = require('../utils/validator')
let { signToken, requireAuth, sanitizeUser, accessTokenExpiresIn } = require('../utils/authHandler')

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(username, password, email,
            "69b1265c33c5468d1c85aad8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return;
        }
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            res.send({
                id: user._id,
                accessToken: signToken({
                    sub: user._id.toString(),
                    username: user.username,
                    email: user.email
                }),
                tokenType: 'Bearer',
                expiresIn: accessTokenExpiresIn
            })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

router.get('/me', requireAuth, async function (req, res, next) {
    res.send(sanitizeUser(req.user))
})

router.post('/change-password', requireAuth, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    try {
        let { oldPassword, newPassword } = req.body
        if (!bcrypt.compareSync(oldPassword, req.user.password)) {
            return res.status(400).send({
                message: 'oldPassword khong chinh xac'
            })
        }
        if (oldPassword === newPassword) {
            return res.status(400).send({
                message: 'newPassword phai khac oldPassword'
            })
        }
        await userController.ChangePassword(req.user._id, newPassword)
        res.send({
            message: 'doi mat khau thanh cong'
        })
    } catch (error) {
        res.status(400).send({
            message: error.message
        })
    }
})
module.exports = router
