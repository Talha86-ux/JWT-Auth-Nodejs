const db = require("../models");
const config = require("../config/auth.config");
const User = db.user;
const Role = db.role;

const Op = db.Sequelize.Op;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = (req, res) => {
    // Save User to Database
    User.create({
      username: req.body.username,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 8)
    })
      .then(user => {
        if (req.body.roles) {
          Role.findAll({
            where: {
              name: {
                [Op.or]: req.body.roles
              }
            }
          }).then(roles => {
            user.setRoles(roles).then(() => {
              res.send({ message: "User was registered successfully!" });
            });
          });
        } else {
          // user role = 1
          user.setRoles([1]).then(() => {
            res.send({ message: "User was registered successfully!" });
          });
        }
      })
      .catch(err => {
        res.status(500).send({ message: err.message });
      });
  };

exports.signin = (req, res) => {
  User.findOne({
    where: {
        username: req.body.username
    }
  }).then(user => {
    if (!user) return res.status(404).send({message: "User not found"});

    var isPasswordValid = bcrypt.compareSync(req.body.password, user.password);

    if (!isPasswordValid) return res.status(401).send({message: "Password didn't match"});   
    
    var token = jwt.sign({id: user.id}, config.secret, {expiresIn: 86400});

    var authorities = [];
    user.getRoles().then(roles => {
        for (var i=0; i<roles.length; i++){
            authorities.push("ROLES_" + roles[i].name.toUpperCase());
        }
    res.status(200).send({
        id: req.id,
        username: req.username,
        email: req.email,
        roles: authorities,
        accessToken: token 
    });    
    });
  })
  .catch(err => {
    res.status(500).send({ message: err.message });
  });
};