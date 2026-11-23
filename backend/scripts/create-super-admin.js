
"use strict";

const readline = require("readline");
const bcrypt = require("bcryptjs");
const db = require("../database/db");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function ask(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}

async function main() {
  try {
    console.log("\n=================================");
    console.log(" DIGITAL AGENT WALLET");
    console.log(" CREATE FIRST SUPER ADMIN");
    console.log("=================================\n");

    const existingAdmin = db.prepare(`
      SELECT id
      FROM users
      WHERE role = ?
      LIMIT 1
    `).get("Super Admin");

    if (existingAdmin) {
      console.log("An riga an ƙirƙiri Super Admin.");
      console.log("Ba za a ƙirƙiri wani ta wannan script ba.");
      process.exitCode = 1;
      return;
    }

    const username = await ask("Username: ");
    const fullName = await ask("Cikakken suna: ");
    const password = await ask("Sabon password (aƙalla haruffa 12): ");
    const confirmPassword = await ask("Sake rubuta password: ");

    if (!username || !fullName || !password) {
      throw new Error("Dole ne a cika dukkan bayanan.");
    }

    if (password.length < 12) {
      throw new Error("Password dole ya kasance aƙalla haruffa 12.");
    }

    if (password !== confirmPassword) {
      throw new Error("Password ɗin biyu ba su yi daidai ba.");
    }

    const existingUser = db.prepare(`
      SELECT id
      FROM users
      WHERE username = ?
      LIMIT 1
    `).get(username);

    if (existingUser) {
      throw new Error("Wannan username yana cikin database. Zaɓi wani.");
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (
        username,
        password_hash,
        full_name,
        role,
        agent_id,
        is_active
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      username,
      passwordHash,
      fullName,
      "Super Admin",
      null,
      1
    );

    console.log("\nAn ƙirƙiri Super Admin cikin nasara.");
    console.log("User ID:", result.lastInsertRowid);
    console.log("Username:", username);
    console.log("Role: SUPER_ADMIN");
    console.log("Password ba a nuna shi ko adana shi a sarari ba.");
    console.log("\nYanzu za ka iya gwada login ɗin.");
  } catch (error) {
    console.error("\nAn samu kuskure:", error.message);
    process.exitCode = 1;
  } finally {
    rl.close();
  }
}

main();
