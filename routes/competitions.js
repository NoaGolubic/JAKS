const express = require("express");
const router = express.Router();
const { authRequired, adminRequired } = require("../services/auth.js");
const Joi = require("joi");
const { db } = require("../services/db.js");

// GET /competitions
router.get("/", authRequired, function (req, res, next) {
    const stmt = db.prepare(`
        SELECT c.id, c.name, c.description, u.name AS author, c.apply_till
        FROM competitions c, users u
        WHERE c.author_id = u.id
        ORDER BY c.apply_till
    `);
    const result = stmt.all();

    res.render("competitions/index", { result: { items: result } });
});

// SCHEMA signup
const schema_id = Joi.object({
    id: Joi.number().integer().positive().required()
});

// GET /competitions/delete/:id
router.get("/delete/:id", adminRequired, function (req, res, next) {
    // do validation
    const result = schema_id.validate(req.params);
    if (result.error) {
        throw new Error("Neispravan poziv");
    }


    const stmt2 = db.prepare("DELETE FROM signed_up WHERE competition_id = ?;");
    const deleteResult2 = stmt2.run(req.params.id);

    const stmt = db.prepare("DELETE FROM competitions WHERE id = ?;");
    const deleteResult = stmt.run(req.params.id);

    

    if (!deleteResult2.changes || !deleteResult.changes || deleteResult.changes||  deleteResult2.changes !== 1) {
        throw new Error("Operacija nije uspjela");
    }

    res.redirect("/competitions");
});

// GET /competitions/edit/:id
router.get("/edit/:id", adminRequired, function (req, res, next) {
    // do validation
    const result = schema_id.validate(req.params);
    if (result.error) {
        throw new Error("Neispravan poziv");
    }

    const stmt = db.prepare("SELECT * FROM competitions WHERE id = ?;");
    const selectResult = stmt.get(req.params.id);

    if (!selectResult) {
        throw new Error("Neispravan poziv");
    }

    res.render("competitions/form", { result: { display_form: true, edit: selectResult } });
});

// SCHEMA edit
const schema_edit = Joi.object({
    id: Joi.number().integer().positive().required(),
    name: Joi.string().min(3).max(50).required(),
    description: Joi.string().min(3).max(1000).required(),
    apply_till: Joi.date().iso().required()
});

// POST /competitions/edit
router.post("/edit", authRequired, function (req, res, next) {
    // do validation
    const result = schema_edit.validate(req.body);
    if (result.error) {
        res.render("competitions/form", { result: { validation_error: true, display_form: true } });
        return;
    }

    const stmt = db.prepare("UPDATE competitions SET name = ?, description = ?, apply_till = ? WHERE id = ?;")
    const updateResult = stmt.run(req.body.name, req.body.description, req.body.apply_till, req.body.id)

    if (updateResult.changes && updateResult.changes === 1) {
        res.redirect("/competitions")
    } else {
        res.render("competitions/form", { result: { database_error: true } });
    }
});


// GET /competitions/add
router.get("/add", adminRequired, function (req, res, next) {
    res.render("competitions/form", { result: { display_form: true } });
});

// SCHEMA add
const schema_add = Joi.object({
    name: Joi.string().min(3).max(50).required(),
    description: Joi.string().min(3).max(1000).required(),
    apply_till: Joi.date().iso().required()
});

// POST /competitions/add
router.post("/add", adminRequired, function (req, res, next) {
    // do validation
    const result = schema_add.validate(req.body);
    if (result.error) {
        res.render("competitions/form", { result: { validation_error: true, display_form: true } });
        return;
    }

    const stmt = db.prepare("INSERT INTO competitions (name, description, author_id, apply_till) VALUES (?, ?, ?, ?);");
    const insertResult = stmt.run(req.body.name, req.body.description, req.user.sub, req.body.apply_till);

    if (insertResult.changes && insertResult.changes === 1) {
        res.render("competitions/form", { result: { success: true } });
    } else {
        res.render("competitions/form", { result: { database_error: true } });
    }
});

// GET /competitions/singup/:id
router.get("/singup/:id", function (req, res, next) {
    // do validation
    const result = schema_id.validate(req.params);
    if (result.error) {
        throw new Error("Neispravan poziv");
    }

    const stmt2 = db.prepare("SELECT * FROM signed_up WHERE user_id = ? AND competition_id = ?");
    const dbResult = stmt2.get(req.user.sub, req.params.id);

    if(dbResult){
        res.render("competitions/form", { result: { alreadySignedUp: true } });
    }
    else{
        const stmt = db.prepare("INSERT INTO signed_up (user_id, competition_id) VALUES (?,?);");
        const singUpResult = stmt.run(req.user.sub, req.params.id)

        if (singUpResult.changes && singUpResult.changes === 1) {
            res.render("competitions/form", { result: { signedUp: true } });
        } else {
            res.render("competitions/form", { result: { database_error: true } });
        }
    }
});

// POST /competition /izmjena bodova  
router.post("/IzmjenaBodova/:id", adminRequired, function (req, res, next) {
    // do validation
    const result = schema_id.validate({ id: req.params.id });
    if (result.error) {
        throw new Error("Greška prilikom izmjene bodova");
    }

    const { bodovi } = req.body;

    const stmt = db.prepare("UPDATE signed_up SET bodovii = ? WHERE id = ?;");
    const updateResult = stmt.run(bodovi, req.params.id);

    if (updateResult.changes && updateResult.changes === 1) {
        res.redirect("/competitions/signedup/" + req.body.competition_id);
    } else {
        throw new Error("Operacija nije uspjela");
    }
});

// GET / competitions/ signup/ ID
router.get("/signedup/:id", function (req, res, next) {
    // do validation
    const result = schema_id.validate(req.params);
    if (result.error) {
        throw new Error("Neispravan poziv");
    }

    const stmt2 = db.prepare("SELECT * FROM signed_up WHERE competition_id = ? ORDER BY bodovii");
    const prikazID = stmt2.all(req.params.id);

    if(prikazID){
        res.render("competitions/signedup", { result: { items: prikazID } });
    }
    else{
        res.render("competitions/signedup", { result: { database_error: true } });
    }
});



    //GET /competitions/ljestvica

router.get("/ljestvica/:id", function (req, res, next) {
    // do validation
    const result = schema_id.validate(req.params);
    if (result.error) {
        throw new Error("Neispravan poziv");
    }

    const stmt = db.prepare("SELECT c.apply_till, c.name AS natjecanje, su.bodovii, u.name FROM signed_up su JOIN competitions c ON su.competition_id = c.id JOIN users u ON su.user_id = u.id WHERE su.competition_id = ? ORDER BY su.bodovii DESC;");
    const resultDB = stmt.all(req.params.id);

    res.render("competitions/ljestvica", { result: { items: resultDB , ljestvica: true} });
})

// POST /competition /editANSW  
router.post("/editAnsw/:id", adminRequired, function (req, res, next) {
    // do validation
    const result = schema_add.validate(req.body);
    if (result.error) {
        throw new Error("Greška prilikom unosa točnih odgovora")
    }

    const stmt = db.prepare("UPDATE signed_up SET bodovii = ? WHERE id = ?;");
    const rezultatIzmjena = stmt.run(req.body.id, req.body.bodovii);

    if (!rezultatIzmjena) {
        throw new Error("Neispravam poziv")
    } else {
        res.redirect("/competitions/signedup/" + req.body.user_id)
    }
});

   


    module.exports = router;