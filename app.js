const express = require('express')
const bodyParser = require('body-parser')
const mysql = require('mysql')
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const app = express()
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcrypt');

const { required } = require("express/lib/response");

const saltRounds = 12;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

var corsOptions = {
    origin: '*',
    optionsSuccessStatus: 200,

    origin: 'http://localhost:8082',
    optionsSuccessStatus: 200
}




app.use(cors(corsOptions));
const pool = mysql.createPool({
    connectionLimit: 100,
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'skript',
    logging: false
})

const sema = Joi.object().keys({

    email: Joi.string().trim().email({ minDomainSegments: 2 }),
    username: Joi.string().trim().min(5).max(40).required(),
    password: Joi.string().trim().min(5).max(12).required(),
    broj_telefona: Joi.string().trim().min(2).max(20).required(),
    steceno_obrazovanje: Joi.string().trim().min(2).max(100).required(),
    id_rola: Joi.number().required(),
    id_radno_mesto: Joi.number().required()


});

const sema_kurs = Joi.object().keys({
    naziv: Joi.string().trim().min(5).max(40).required(),
    trajanje: Joi.string().trim().min(5).max(12).required(),
    uslov_polaganja: Joi.string().trim().min(2).max(20).required()

});

const sema_radno_mesto = Joi.object().keys({
    naziv: Joi.string().trim().min(5).max(40).required(),
    opis: Joi.string().trim().min(5).max(500).required()


});

const sema_polaganje = Joi.object().keys({
    id_kursa: Joi.number().required(),
    id_usera: Joi.number().required(),
    ocena: Joi.number().required(),
    zavrsen: Joi.boolean().required()
});


function authAdmin(req, res, next) {
    if (req.headers.authorization == null) return res.json({ msg: "Niste logovani" });

    const token = req.headers.authorization.split(" ")[1];

    user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    pool.getConnection((err, connection) => {
        if (err) throw err

        connection.query('SELECT * FROM app_user WHERE id=?', user.id, (err, rows) => {
            connection.release() // return the connection to pool

            if (!err) {

                if (rows[0].id_rola == 1) {
                    next();
                } else {
                    res.json({ msg: "Niste administrato" });
                }

            } else {
                console.log(err)
            }

        })

    })
};

function authModerator(req, res, next) {

   
    if (req.headers.authorization == null) return res.json({ msg: "Niste logovani" });

    const token = req.headers.authorization.split(" ")[1];
   
    user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    pool.getConnection((err, connection) => {
        if (err) throw err

        connection.query('SELECT * FROM app_user WHERE id=?', user.id, (err, rows) => {
            connection.release() // return the connection to pool
             console.log(user.id);

            if (!err) {

                if (rows[0].id_rola == 1 || rows[0].id_rola == 2) {
                    
                    next();
                } else {
                    console.log(rows.id_rola);
                    res.json({ msg: "Niste administrator ili moderator" });
                }

            } else {
                console.log(err)
            }

        })

    })
};
function authToken(req, res, next) {

    if (req.headers.authorization == null) {

        return res.json({ msg: "Nije poslat auth heder" })

    } else {
        const token = req.headers.authorization.split(" ")[1];


        if (token == null) return res.json({ msg: "Niste logovani" });

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {


            if (err) return res.json({ msg: "Pogresan token" });


            next();
        });
    }

};

//prikaz svih usera
app.get('/listUsers', authToken, (req, res) => {

    pool.getConnection((err, connection) => {
        if (err) throw err


        connection.query('SELECT * FROM app_user', (err, rows) => {
            connection.release() // return the connection to pool

            if (!err) {

                res.json(rows);
            } else {
                console.log(err)
            }


        })
    })
})


//dodavanje usera
app.post('/addUser', authAdmin, (req, res) => {

    Joi.validate(req.body, sema, (err, result) => {

        if (err) {
            res.send(err);
        } else {
        console.log("prosao joi")
            pool.getConnection((err, connection) => {
                if (err) throw err
                const params = req.body
                bcrypt.genSalt(saltRounds, function (err, salt) {
                    bcrypt.hash(req.body.password, salt, function (err, hash) {
                        params.password = hash;

                        connection.query('INSERT INTO app_user SET ?', params, (err, rows) => {
                            connection.release() // return the connection to pool
                            if (!err) {
                                res.json({ msg: "Korisnik je" })
                            } else {
                                res.json({ msg: "Korisnik vec postoji" })
                            }


                        })
                    })

                });
            });

        }

    })




});

//brisanje usera
app.delete('/deleteUser/:id', authAdmin, (req, res) => {

    pool.getConnection((err, connection) => {
        if (err) throw err
        connection.query('DELETE FROM app_user WHERE id = ?', [req.params.id], (err, rows) => {
            connection.release() // return the connection to pool
            if (!err) {
                res.send(`User with the record ID ${[req.params.id]} has been removed.`)
            } else {
                console.log(err)
            }

            console.log('The data from user table are: \n', rows)
        })
    })
});

// Update a record / user
app.put('/updateUser/:id',authAdmin, (req, res) => {

    pool.getConnection((err, connection) => {
        if (err) throw err

        const pass = bcrypt.hashSync(req.body.password, 12);

        const { id, username, password, email, broj_telefona, steceno_obrazovanje, id_radno_mesto } = req.body

        Joi.validate(req.body, sema, (error, result) => {
            if (error) {
                res.send(error)
            } else {
                connection.query('UPDATE app_user SET username = ?, password = ?, email = ?, broj_telefona = ?, steceno_obrazovanje = ?, id_radno_mesto = ?  WHERE id = ?', [username, pass, email, broj_telefona, steceno_obrazovanje, id_radno_mesto, req.params.id], (err, rows) => {
                    connection.release() // return the connection to pool

                    if (!err) {
                        res.send(`User with the name: ${username} has been added.`)
                    } else {
                        res.send(err);
                    }

                })
            }
        })
    })
})

//prikaz dostupnih kurseva
app.get('/listKursevi', authToken, (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err

        connection.query('SELECT * FROM dostuni_kursevi', (err, rows) => {
            connection.release() // return the connection to pool

            if (!err) {
                
                res.json(rows);
            } else {
                console.log(err)
            }

            // if(err) throw err
            
        })
    })
})

//dodavanje kursa
app.post('/addKurs', authModerator ,(req, res) => {

    Joi.validate(req.body, sema_kurs, (error, result) => {

        if (error) {
            res.send(error);
        } else {
            pool.getConnection((err, connection) => {
                if (err) throw err

                const params = req.body
                connection.query('INSERT INTO dostuni_kursevi SET ?', params, (err, rows) => {
                    connection.release() // return the connection to pool
                    if (!err) {
                        res.send(`Kurs with the record ID  has been added.`)
                    } else {
                        console.log(err)
                    }


                })
            })
        }
    })

});

//brisanje kursa
app.delete('/deleteKurs/:id', authModerator, (req, res) => {

    pool.getConnection((err, connection) => {
        if (err) throw err
        connection.query('DELETE FROM dostuni_kursevi WHERE id = ?', [req.params.id], (err, rows) => {
            connection.release() // return the connection to pool
            if (!err) {
                res.send(`kurs with the record ID ${[req.params.id]} has been removed.`)
            } else {
                console.log(err)
            }

            console.log('The data from kurs table are: \n', rows)
        })
    })
});

// Update kursa
app.put('/updateKurs/:id', authModerator ,(req, res) => {


    Joi.validate(req.body, sema_kurs, (error, result) => {

        if (error) {
            res.send(error);
        } else {


            pool.getConnection((err, connection) => {
                if (err) throw err


                const { id, naziv, trajanje, uslov_polaganja } = req.body

                connection.query('UPDATE dostuni_kursevi SET naziv = ?, trajanje = ?, uslov_polaganja = ? WHERE id=? ', [naziv, trajanje, uslov_polaganja, req.params.id], (err, rows) => {
                    connection.release() // return the connection to pool

                    if (!err) {
                        res.send(`User with the name: ${naziv} has been added.`)
                    } else {
                        console.log(err)
                    }

                })

                console.log(req.body)
            })
        }

    });
})

app.get('/listRadnaMesta', authToken, (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err

        connection.query('SELECT * FROM radna_mesta', (err, rows) => {
            connection.release() // return the connection to pool

            if (!err) {
             
                res.json(rows);
            } else {
                console.log(err)
            }

            // if(err) throw err
            console.log('The data from app_user table are: \n', rows)
        })
    })
})
app.post('/addRadnoMesto', authModerator,(req, res) => {

    Joi.validate(req.body, sema_radno_mesto, (error, result) => {

        if (error) {
            res.send(error);
        } else {
            pool.getConnection((err, connection) => {
                if (err) throw err

                const params = req.body
                connection.query('INSERT INTO radna_mesta SET ?', params, (err, rows) => {
                    connection.release() // return the connection to pool
                    if (!err) {
                        res.send(`Radno mesto with the record ID  has been added.`)
                    } else {
                        console.log(err)
                    }


                })
            })
        }
    })
});

//brisanje usera
app.delete('/deleteRadnoMesto/:id', authModerator, (req, res) => {

    pool.getConnection((err, connection) => {
        if (err) throw err
        connection.query('DELETE FROM radna_mesta WHERE id = ?', [req.params.id], (err, rows) => {
            connection.release() // return the connection to pool
            if (!err) {
                res.send(`User with the record ID ${[req.params.id]} has been removed.`)
            } else {
                console.log(err)
            }

        })
    })
});

// Update a record /
app.put('/updateRadnoMesto/:id',authModerator , (req, res) => {


    Joi.validate(req.body, sema_radno_mesto, (error, result) => {
        if (error) {
            res.send(error);
        } else {



            pool.getConnection((err, connection) => {
                if (err) throw err


                const { id, naziv, opis } = req.body

                connection.query('UPDATE radna_mesta SET naziv = ?, opis = ? WHERE id=? ', [naziv, opis,req.params.id], (err, rows) => {
                    connection.release() // return the connection to pool

                    if (!err) {
                        res.send("Radno mesto update")
                    } else {
                        console.log(err)
                    }

                })


            })
        }
    });
})



app.get('/listIstorijaPolaganja', authToken, (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err

        connection.query('SELECT * FROM istorija_polaganja_kurseva', (err, rows) => {
            connection.release() // return the connection to pool

            if (!err) {
                
                res.json(rows);
            } else {
                console.log(err)
            }

            // if(err) throw err
            console.log('The data from app_user table are: \n', rows)
        })
    })


})

app.post('/addIstorijaPolaganja', authModerator ,(req, res) => {

    Joi.validate(req.body, sema_polaganje, (error, result) => {

        if (error) {
            res.send(error);
        } else {
            pool.getConnection((err, connection) => {
                if (err) throw err

                const params = req.body
                connection.query('INSERT INTO istorija_polaganja_kurseva SET ?', params, (err, rows) => {
                    connection.release() // return the connection to pool
                    if (!err) {
                        res.send(`Radno mesto with the record ID  has been added.`)
                    } else {
                        console.log(err)
                    }


                })
            })
        }
    })
});

//brisanje usera
app.delete('/deleteIstorija/:id', authModerator, (req, res) => {

    pool.getConnection((err, connection) => {
        if (err) throw err
        connection.query('DELETE FROM istorija_polaganja_kurseva WHERE id = ?', [req.params.id], (err, rows) => {
            connection.release() // return the connection to pool
            if (!err) {
                res.send(`User with the record ID ${[req.params.id]} has been removed.`)
            } else {
                console.log(err)
            }

        })
    })
});

// Update a record /
app.put('/updateIstorija/:id',authModerator, (req, res) => {

    Joi.validate(req.body, sema_polaganje, (error, result) => {
        if (error) {
            res.send(error);
        } else {

            pool.getConnection((err, connection) => {
                if (err) throw err

                const { id, id_kursa, id_usera, ocena, zavrsen } = req.body

                connection.query('UPDATE istorija_polaganja_kurseva SET id_kursa = ?, id_usera = ?, ocena = ?, zavrsen = ? WHERE id=? ', [id_kursa, id_usera, ocena, zavrsen,req.params.id], (err, rows) => {
                    connection.release() // return the connection to pool

                    if (!err) {
                        res.send("Istorija polaganja update")
                    } else {
                        console.log(err)
                    }

                })

                console.log(req.body)
            })
        }
    })
});



app.listen(8081)