const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken')

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const { email, password, firstName, lastName, country, image, frontBaseUrl} = req.body;
    const hashPassword = await bcrypt.hash(password, 10);
    const body = { email, firstName, lastName, country, image, password:hashPassword};
    const result = await User.create(body);

    const code = require('crypto').randomBytes(64).toString('hex');
    const url = `${frontBaseUrl}/verify_email/${code}`

    await sendEmail({
        to: email,
        subject: `Correo de verificación de cuenta`,
        html: `
        <h2>Haz click en el siguiente enlace para verificar tu cuenta</h2>
        <a href=${url}> Confirmar </a>
        `
    });

    const bodyCode = {code, userId: result.id}
    await EmailCode.create(bodyCode)

    
    
    return res.status(201).json(result);
});


const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    const result =  await User.destroy({ where: {id} });
    if(!result) return res.sendStatus(404);
    return res.status(201).json({message: 'User deleted successfully'})
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async (req,res)=>{ // /verify/:code
    const {code} = req.params

    const codeUser = await EmailCode.findOne({where:{code}})
    if(!codeUser) return res.sendStatus(401)


    const body = {isVerified:true}

    const userUpdate = await User.update(
        body,
        {where:{id:codeUser.userId}, returning:true}
    )
    await codeUser.destroy()

    return res.json(userUpdate[1][0])

});

const login = catchError(async(req, res) => {

    const { email, password } = req.body;
    const user = await User.findOne({where: {email}});

    if(!user) return res.status(401).json({message:'invalid credentials'});

    const isValidPassword = await bcrypt.compare(password, user.password);
    if(!isValidPassword) return res.status(401).json({message:'invalid credentials'});

    if(!user.isVerified) return res.status(401).json({message: 'invalid credentials'})

    const token = jwt.sign(
        {user},
        process.env.TOKEN_SECRET,
        {expiresIn: '1d'}
    )
    return res.json({user, token})
});

const logged = catchError(async(req, res) => {
    return res.json(req.user)
})

const resetPassword = catchError(async(req, res) => {
    const { email, frontBaseUrl } = req.body;
    const user = await User.findOne({where: {email}})
    if(!user) return res.sendStatus(401)
    const code = require('crypto').randomBytes(64).toString('hex')
    const url = `
    ${frontBaseUrl}/reset_password/${code}`

    await sendEmail({
        to: email,
        subject: `Solicitud de cambio de contraseña`,
        html: `
        <h2>Haz click en el siguiente enlace para cambiar la contraseña</h2>
        <a href=${url}> Click aquí</a>
        `
    });

    const body = {code, userId: user.id}

    await EmailCode.create(body)

    return res.json(user)
});

const updatePassword = catchError(async(req, res) => {
    //reset_password/:code
    const { code } = req.params;
    const { password } = req.body;

    const userCode = await EmailCode.findOne({where:{code}})
    if(!userCode) return res.sendStatus(401);
    
    const hashPassword = await bcrypt.hash(password, 10);
    const body = {password: hashPassword};
    
    const user = await User.update(body, {where:{id: userCode.userId}})
    
    if(user[0] === 0) return res.sendStatus(404);
    await userCode.destroy()

    return res.status(201).json({message:'your password has been successfully changed'})
})

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    login,
    logged,
    resetPassword,
    updatePassword
}