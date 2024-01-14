var express = require('express');
var router = express.Router();

/* Módulo jsonwebtoken */
const jwt = require('jsonwebtoken');

/* Módulo crypto */
let crypto = require('crypto');

const Users = require('../models').users;
const Roles = require('../models').roles;
const UsersRoles = require('../models').users_roles;
const { Op } = require("sequelize");

/* GET users listing. */
router.get('/getToken', function (req, res, next) {
  
  /* Lee las cookies "jwt-token" y "error" */
  let token = req.cookies['jwt-token']
  let error = req.cookies['error']

  /* Renderiza el contenido de las cookies en la vista */
  res.render('gettoken', { title: 'User Login', token: token, error: error });

});

router.post('/register', async (req, res,next) => {

  // Parámetros en el cuerpo del requerimiento
  let { name, password, roleName } = req.body;

  try {

      // Encripte la contraseña con SALT
      let salt = process.env.SALT
      let hash = crypto.createHmac('sha512',salt).update(password).digest("base64");
      let passwordHash = salt + "$" + hash

      // Guarde los datos del usuario
      let user = await Users.create({ name: name, password: passwordHash })

      // Obtenga el rol en función del nombre
      let role = await Roles.findOne({ 
        where: { 
          [Op.and]: [
            {name: roleName}
          ]
        } 
      })

      // Cree la relación usuario-rol
      await UsersRoles.create({ users_iduser: user.iduser, roles_idrole: role.idrole })

      // Redirige a la página de registros
      res.redirect('/users')

  } catch (error) {
      res.status(400).send(error)
  }

})

router.post('/generateToken', async (req, res,next) => {

  // Parámetros en el cuerpo del requerimiento
  let { name, password } = req.body;

  try {

    // Encripte la contraseña
    let salt = process.env.SALT
    let hash = crypto.createHmac('sha512', salt).update(password).digest("base64");
    let passwordHash = salt + "$" + hash

    /* Obtenga el usuario y su rol */
    let user = await Users.findOne({ where: { [Op.and]: [ { name: name }, { password: passwordHash } ] } })
    let relations = await UsersRoles.findOne({ where: { [Op.and]: [ { users_iduser: user.iduser } ] } });
    let roles = await Roles.findOne({ where: { [Op.and]: [ { idrole: relations.roles_idrole } ] } });

    /* Genera el token con los datos encriptados */
    const accessToken = jwt.sign({ name: user.name, role: roles.name }, process.env.TOKEN_SECRET);

    res.json({ accessToken });

      } catch (error) {
          res.status(400).send(error)
      }

  });

  router.post('/postToken', async (req, res,next) => {

    // Parámetros en el cuerpo del requerimiento
    let { name, password } = req.body;
  
    try {
  
      // Encripte la contraseña
      let salt = process.env.SALT
      let hash = crypto.createHmac('sha512', salt).update(password).digest("base64");
      let passwordHash = salt + "$" + hash
  
      /* Obtenga el usuario y su rol */
      let user = await Users.findOne({ where: { [Op.and]: [ { name: name }, { password: passwordHash } ] } })
      let relations = await UsersRoles.findOne({ where: { [Op.and]: [ { users_iduser: user.iduser } ] } });
      let roles = await Roles.findOne({ where: { [Op.and]: [ { idrole: relations.roles_idrole } ] } });
  
      /* Genera el token con los datos encriptados */
      const accessToken = jwt.sign({ name: user.name, role: roles.name }, process.env.TOKEN_SECRET);
  
      /* Tiempo de expiración de la cookie: 30 segundos */
      const options = {
        expires: new Date(
          Date.now() + 30 * 1000
        )
      }
  
      /* Crea la cookie "jwt-token" con el accessToken */
      res.cookie("jwt-token", accessToken, options)
  
      /* Redirección al controlador para el verbo HTTP GET con la ruta /getToken */
      res.redirect('/users/getToken')
  
  
    } catch (error) {
        
      /* En caso de error, elimina la cookie */
      res.clearCookie('jwt-token')
  
      /* Tiempo de expiración de la cookie: 10 segundos */
      const options = {
        expires: new Date(
          Date.now() + 10 * 1000
        )
      }
          
      res.cookie("error", "No token generated", options)
  
      /* Redirige a la página original */
      res.redirect('/users/getToken')
  
    }
  
  });

module.exports = router;
