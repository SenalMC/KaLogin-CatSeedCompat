package org.katacr.kalogin

import java.io.File
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.CompletableFuture

class DatabaseManager(private val plugin: KaLogin) {

    private var connection: Connection? = null
    private var databaseType: String = "sqlite"

    val isCatSeedMode: Boolean
        get() = databaseType == "catseed-sqlite"

    val isCatSeedReadOnly: Boolean
        get() = plugin.config.getBoolean("catseed.readonly", true)

    fun init() {
        val config = plugin.config
        databaseType = config.getString("database.type", "sqlite")?.lowercase() ?: "sqlite"

        try {
            when (databaseType) {
                "mysql" -> {
                    val host = config.getString("database.mysql.host")
                    val port = config.getInt("database.mysql.port")
                    val db = config.getString("database.mysql.database")
                    val user = config.getString("database.mysql.username")
                    val pass = config.getString("database.mysql.password")
                    val params = config.getString("database.mysql.params", "")

                    val url = "jdbc:mysql://$host:$port/$db$params"
                    connection = DriverManager.getConnection(url, user, pass)
                    plugin.logger.info("已成功连接到 MySQL 数据库")
                    createTable()
                }

                "catseed-sqlite" -> {
                    val path = config.getString("catseed.sqlite-file", "") ?: ""
                    if (path.isBlank()) {
                        throw IllegalArgumentException("catseed.sqlite-file 不能为空，请填写 CatSeedLogin accounts.db 的完整路径")
                    }
                    val dbFile = File(path)
                    if (!dbFile.exists()) {
                        throw IllegalArgumentException("CatSeedLogin 数据库不存在: ${dbFile.absolutePath}")
                    }
                    Class.forName("org.sqlite.JDBC")
                    connection = DriverManager.getConnection("jdbc:sqlite:${dbFile.absolutePath}")
                    plugin.logger.info("已成功连接到 CatSeedLogin SQLite 数据库: ${dbFile.absolutePath}")
                    plugin.logger.info("CatSeedLogin 兼容模式已启用，readonly=${isCatSeedReadOnly}")
                }

                else -> {
                    val fileName = config.getString("database.sqlite.file_name", "data.db")
                    val dbFile = File(plugin.dataFolder, fileName!!)
                    if (!dbFile.exists()) {
                        plugin.dataFolder.mkdirs()
                        dbFile.createNewFile()
                    }
                    Class.forName("org.sqlite.JDBC")
                    connection = DriverManager.getConnection("jdbc:sqlite:${dbFile.absolutePath}")
                    plugin.logger.info("已成功连接到 SQLite 数据库")
                    createTable()
                }
            }
        } catch (e: Exception) {
            plugin.logger.severe("数据库初始化失败: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun createTable() {
        val sql = """
            CREATE TABLE IF NOT EXISTS kalogin_users (
                uuid VARCHAR(36) PRIMARY KEY,
                username VARCHAR(16),
                password TEXT,
                ip VARCHAR(45),
                last_login_ip VARCHAR(45),
                auto_login_by_ip BOOLEAN DEFAULT FALSE,
                reg_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """.trimIndent()

        connection?.createStatement()?.use { it.execute(sql) }
        addColumnIfNotExists("last_login_ip", "VARCHAR(45)")
        addColumnIfNotExists("auto_login_by_ip", "BOOLEAN DEFAULT FALSE")
    }

    private fun addColumnIfNotExists(columnName: String, columnType: String) {
        try {
            val tableName = "kalogin_users"
            val sql = "SELECT COUNT(*) FROM pragma_table_info('$tableName') WHERE name = '$columnName'"
            val columnExists = connection?.createStatement()?.executeQuery(sql)?.use { rs ->
                rs.next() && rs.getInt(1) > 0
            } ?: false

            if (!columnExists) {
                val alterSql = "ALTER TABLE kalogin_users ADD COLUMN $columnName $columnType"
                connection?.createStatement()?.execute(alterSql)
                plugin.logger.info("已添加数据库字段: $columnName")
            }
        } catch (e: SQLException) {
            try {
                val alterSql = "ALTER TABLE kalogin_users ADD COLUMN $columnName $columnType"
                connection?.createStatement()?.execute(alterSql)
            } catch (_: SQLException) {
            }
        }
    }

    fun getConnection(): Connection? {
        try {
            if (connection == null || connection!!.isClosed) {
                init()
            }
        } catch (e: SQLException) {
            e.printStackTrace()
        }
        return connection
    }

    private fun catSeedTable(): String = plugin.config.getString("catseed.table", "accounts") ?: "accounts"
    private fun catSeedUsernameColumn(): String = plugin.config.getString("catseed.columns.username", "name") ?: "name"
    private fun catSeedPasswordColumn(): String = plugin.config.getString("catseed.columns.password", "password") ?: "password"
    private fun catSeedIpColumn(): String = plugin.config.getString("catseed.columns.ips", "ips") ?: "ips"
    private fun catSeedLastActionColumn(): String = plugin.config.getString("catseed.columns.last-action", "lastAction") ?: "lastAction"

    private fun catSeedTimestamp(): String {
        return SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.ROOT).format(Date())
    }

    private fun sha512Hex(input: String): String {
        val bytes = input.toByteArray(Charsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-512").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun sha512HexCatSeedBugCompatible(input: String): String {
        val bytes = input.toByteArray(Charsets.UTF_8)
        val md = MessageDigest.getInstance("SHA-512")

        // CatSeedLogin 1.3.5 has a historical bug:
        // MessageDigest.update(raw.getBytes(UTF_8), 0, raw.length())
        // It uses character length as byte length. Because its salt contains non-ASCII chars,
        // hashing the full UTF-8 byte array will NOT match existing CatSeedLogin accounts.db.
        md.update(bytes, 0, input.length)
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * CatSeedLogin 1.3.5 exact password algorithm.
     *
     * Decompilation note:
     * javap displays some salt characters as '?', but the real constant-pool bytes are:
     * prefix = "\u00DC\u00C4aeut//&/=I "
     * middle = "7421\u20AC547"
     * suffix = "__+I\u00C4IH\u00A7%NK "
     *
     * cc.baka9.catseedlogin.util.Crypt.encrypt(name, password):
     * SHA-512 over only raw.length UTF-8 bytes, not the full byte array.
     *
     * Important: player name participates in the hash. Use the name stored in accounts.name
     * when verifying existing accounts to avoid case mismatch problems.
     */
    private fun catSeedHash(name: String, password: String): String {
        val raw = "\u00DC\u00C4aeut//&/=I " +
                password +
                "7421\u20AC547" +
                name +
                "__+I\u00C4IH\u00A7%NK " +
                password
        return sha512HexCatSeedBugCompatible(raw)
    }

    private fun catSeedNameLookup(username: String): String =
        if (plugin.config.getBoolean("catseed.username-ignore-case", true)) username.lowercase() else username

    fun registerPlayer(uuid: UUID, username: String, password: String, ip: String): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode && isCatSeedReadOnly) {
                plugin.logger.warning("CatSeedLogin readonly 模式下已阻止注册写入: $username")
                return@supplyAsync false
            }

            if (isCatSeedMode) {
                val hashedPassword = catSeedHash(username, password)
                val sql = "INSERT INTO ${catSeedTable()} (${catSeedUsernameColumn()}, ${catSeedPasswordColumn()}, ${catSeedIpColumn()}, ${catSeedLastActionColumn()}) VALUES (?, ?, ?, ?)"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, username)
                        ps.setString(2, hashedPassword)
                        ps.setString(3, ip)
                        ps.setString(4, catSeedTimestamp())
                        ps.executeUpdate() > 0
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace()
                    false
                }
            } else {
                val hashedPassword = PasswordHasher.hash(password)
                val sql = "INSERT INTO kalogin_users (uuid, username, password, ip, last_login_ip, auto_login_by_ip) VALUES (?, ?, ?, ?, ?, FALSE)"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, uuid.toString())
                        ps.setString(2, username)
                        ps.setString(3, hashedPassword)
                        ps.setString(4, ip)
                        ps.setString(5, ip)
                        ps.executeUpdate()
                        true
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace()
                    false
                }
            }
        })
    }

    fun isPlayerRegistered(uuid: UUID): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) {
                val username = plugin.server.getPlayer(uuid)?.name ?: return@supplyAsync false
                val op = if (plugin.config.getBoolean("catseed.username-ignore-case", true)) "LOWER(${catSeedUsernameColumn()}) = ?" else "${catSeedUsernameColumn()} = ?"
                val sql = "SELECT COUNT(*) FROM ${catSeedTable()} WHERE $op"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, catSeedNameLookup(username))
                        ps.executeQuery()?.use { rs ->
                            rs.next(); rs.getInt(1) > 0
                        }
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            } else {
                val sql = "SELECT COUNT(*) FROM kalogin_users WHERE uuid = ?"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, uuid.toString())
                        ps.executeQuery()?.use { rs ->
                            rs.next(); rs.getInt(1) > 0
                        }
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            }
        })
    }

    fun initPlayerForAuthMe(uuid: UUID, username: String, ip: String): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) return@supplyAsync true
            val sql = "INSERT INTO kalogin_users (uuid, username, last_login_ip, auto_login_by_ip) VALUES (?, ?, ?, FALSE)"
            try {
                getConnection()?.prepareStatement(sql)?.use { ps ->
                    ps.setString(1, uuid.toString())
                    ps.setString(2, username)
                    ps.setString(3, ip)
                    ps.executeUpdate()
                    true
                }
            } catch (e: SQLException) {
                try {
                    val updateSql = "UPDATE kalogin_users SET username = ?, last_login_ip = ? WHERE uuid = ?"
                    getConnection()?.prepareStatement(updateSql)?.use { ps ->
                        ps.setString(1, username)
                        ps.setString(2, ip)
                        ps.setString(3, uuid.toString())
                        ps.executeUpdate() > 0
                    } ?: false
                } catch (e2: SQLException) {
                    e.printStackTrace(); false
                }
            }
        })
    }

    fun canAutoLogin(uuid: UUID, ip: String): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) return@supplyAsync false
            val sql = "SELECT last_login_ip, auto_login_by_ip FROM kalogin_users WHERE uuid = ?"
            try {
                getConnection()?.prepareStatement(sql)?.use { ps ->
                    ps.setString(1, uuid.toString())
                    ps.executeQuery()?.use { rs ->
                        if (rs.next()) {
                            val lastIp = rs.getString("last_login_ip")
                            val autoLoginByIp = rs.getBoolean("auto_login_by_ip")
                            autoLoginByIp && (lastIp != null && lastIp == ip)
                        } else false
                    }
                } ?: false
            } catch (e: SQLException) {
                e.printStackTrace(); false
            }
        })
    }

    fun isSameLastIp(uuid: UUID, ip: String): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) return@supplyAsync false
            val sql = "SELECT last_login_ip FROM kalogin_users WHERE uuid = ?"
            try {
                getConnection()?.prepareStatement(sql)?.use { ps ->
                    ps.setString(1, uuid.toString())
                    ps.executeQuery()?.use { rs ->
                        if (rs.next()) {
                            val lastIp = rs.getString("last_login_ip")
                            lastIp != null && lastIp == ip
                        } else false
                    }
                } ?: false
            } catch (e: SQLException) {
                e.printStackTrace(); false
            }
        })
    }

    fun updateAutoLoginByIp(uuid: UUID, enabled: Boolean): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) return@supplyAsync true
            val sql = "UPDATE kalogin_users SET auto_login_by_ip = ? WHERE uuid = ?"
            try {
                getConnection()?.prepareStatement(sql)?.use { ps ->
                    ps.setBoolean(1, enabled)
                    ps.setString(2, uuid.toString())
                    ps.executeUpdate()
                    true
                } ?: false
            } catch (e: SQLException) {
                e.printStackTrace(); false
            }
        })
    }

    fun updateLastLoginIp(uuid: UUID, ip: String): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) {
                if (isCatSeedReadOnly) return@supplyAsync true
                val username = plugin.server.getPlayer(uuid)?.name ?: return@supplyAsync false
                val op = if (plugin.config.getBoolean("catseed.username-ignore-case", true)) "LOWER(${catSeedUsernameColumn()}) = ?" else "${catSeedUsernameColumn()} = ?"
                val sql = "UPDATE ${catSeedTable()} SET ${catSeedIpColumn()} = ?, ${catSeedLastActionColumn()} = ? WHERE $op"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, ip)
                        ps.setString(2, catSeedTimestamp())
                        ps.setString(3, catSeedNameLookup(username))
                        ps.executeUpdate() > 0
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            } else {
                val sql = "UPDATE kalogin_users SET last_login_ip = ? WHERE uuid = ?"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, ip)
                        ps.setString(2, uuid.toString())
                        ps.executeUpdate()
                        true
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            }
        })
    }

    fun verifyPassword(uuid: UUID, password: String): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) {
                val username = plugin.server.getPlayer(uuid)?.name ?: return@supplyAsync false
                val op = if (plugin.config.getBoolean("catseed.username-ignore-case", true)) "LOWER(${catSeedUsernameColumn()}) = ?" else "${catSeedUsernameColumn()} = ?"
                val sql = "SELECT ${catSeedUsernameColumn()}, ${catSeedPasswordColumn()} FROM ${catSeedTable()} WHERE $op LIMIT 1"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, catSeedNameLookup(username))
                        ps.executeQuery()?.use { rs ->
                            if (rs.next()) {
                                val storedName = rs.getString(catSeedUsernameColumn()) ?: username
                                val hashedPassword = rs.getString(catSeedPasswordColumn()) ?: return@use false
                                catSeedHash(storedName, password).equals(hashedPassword.trim(), ignoreCase = true)
                            } else false
                        }
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            } else {
                val sql = "SELECT password FROM kalogin_users WHERE uuid = ?"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, uuid.toString())
                        ps.executeQuery()?.use { rs ->
                            if (rs.next()) {
                                val hashedPassword = rs.getString("password")
                                PasswordHasher.check(password, hashedPassword)
                            } else false
                        }
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            }
        })
    }

    fun countAccountsByIp(ip: String): CompletableFuture<Int> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) return@supplyAsync 0
            val sql = "SELECT COUNT(*) FROM kalogin_users WHERE ip = ?"
            try {
                getConnection()?.prepareStatement(sql)?.use { ps ->
                    ps.setString(1, ip)
                    ps.executeQuery()?.use { rs -> if (rs.next()) rs.getInt(1) else 0 }
                } ?: 0
            } catch (e: SQLException) {
                e.printStackTrace(); 0
            }
        })
    }

    fun deletePlayer(uuid: UUID): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) {
                if (isCatSeedReadOnly) return@supplyAsync false
                val username = plugin.server.getOfflinePlayer(uuid).name ?: return@supplyAsync false
                val op = if (plugin.config.getBoolean("catseed.username-ignore-case", true)) "LOWER(${catSeedUsernameColumn()}) = ?" else "${catSeedUsernameColumn()} = ?"
                val sql = "DELETE FROM ${catSeedTable()} WHERE $op"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, catSeedNameLookup(username))
                        ps.executeUpdate() > 0
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            } else {
                val sql = "DELETE FROM kalogin_users WHERE uuid = ?"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, uuid.toString())
                        ps.executeUpdate() > 0
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            }
        })
    }

    fun setPassword(uuid: UUID, password: String): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync({
            if (isCatSeedMode) {
                if (isCatSeedReadOnly) return@supplyAsync false
                val username = plugin.server.getOfflinePlayer(uuid).name ?: return@supplyAsync false
                val op = if (plugin.config.getBoolean("catseed.username-ignore-case", true)) "LOWER(${catSeedUsernameColumn()}) = ?" else "${catSeedUsernameColumn()} = ?"
                val sql = "UPDATE ${catSeedTable()} SET ${catSeedPasswordColumn()} = ?, ${catSeedLastActionColumn()} = ? WHERE $op"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, catSeedHash(username, password))
                        ps.setString(2, catSeedTimestamp())
                        ps.setString(3, catSeedNameLookup(username))
                        ps.executeUpdate() > 0
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            } else {
                val hashedPassword = PasswordHasher.hash(password)
                val sql = "UPDATE kalogin_users SET password = ? WHERE uuid = ?"
                try {
                    getConnection()?.prepareStatement(sql)?.use { ps ->
                        ps.setString(1, hashedPassword)
                        ps.setString(2, uuid.toString())
                        ps.executeUpdate() > 0
                    } ?: false
                } catch (e: SQLException) {
                    e.printStackTrace(); false
                }
            }
        })
    }

    fun close() {
        connection?.close()
    }
}
