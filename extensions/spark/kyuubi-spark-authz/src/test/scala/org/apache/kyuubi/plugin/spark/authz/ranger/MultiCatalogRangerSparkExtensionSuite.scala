/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kyuubi.plugin.spark.authz.ranger

import java.sql.DriverManager

import scala.util.Try

import org.apache.kyuubi.plugin.spark.authz.AccessControlException
import org.apache.kyuubi.plugin.spark.authz.RangerTestNamespace._
import org.apache.kyuubi.plugin.spark.authz.RangerTestUsers._
import org.apache.kyuubi.plugin.spark.authz.V2JdbcTableCatalogPrivilegesBuilderSuite._
import org.apache.kyuubi.plugin.spark.authz.util.AuthZUtils._
import org.apache.kyuubi.util.AssertionUtils._

/**
 * Tests for RangerSparkExtensionSuite with multiple catalogs,
 * catalog `catalog2` is mapped to Ranger service `hive_jenkins_catalog2` by
 * `ranger.plugin.spark.catalog.catalog2.service.name`,
 * while `spark_catalog` uses the default Ranger service `hive_jenkins`.
 */
class MultiCatalogRangerSparkExtensionSuite extends RangerSparkExtensionSuite {
  override protected val catalogImpl: String = "in-memory"
  override protected val supportPurge: Boolean = false

  val catalogV2 = "catalog2"
  val table1 = "table1"
  val table2 = "table2"

  val dbUrl = s"jdbc:derby:memory:$catalogV2"
  val jdbcUrl: String = s"$dbUrl;create=true"

  override def beforeAll(): Unit = {
    spark.conf.set(s"spark.sql.catalog.$catalogV2", v2JdbcTableCatalogClassName)
    spark.conf.set(s"spark.sql.catalog.$catalogV2.url", jdbcUrl)
    spark.conf.set(s"spark.sql.catalog.$catalogV2.driver", derbyJdbcDriverClass)

    super.beforeAll()
  }

  override def afterAll(): Unit = {
    super.afterAll()
    spark.sessionState.catalog.reset()
    spark.sessionState.conf.clear()

    // cleanup db
    Try {
      DriverManager.getConnection(s"$dbUrl;shutdown=true")
    }
  }

  test("get or create Ranger plugin by catalog name") {
    val defaultPlugin = SparkRangerAdminPlugin.getOrCreate()
    assert(defaultPlugin.getServiceName === "hive_jenkins")
    assert(defaultPlugin.getAppId === SparkRangerAdminPlugin.defaultAppId)
    assert(SparkRangerAdminPlugin.getOrCreate(Some(sparkCatalog)) eq defaultPlugin)
    // fallback to the default plugin for catalog without Ranger service configured
    assert(SparkRangerAdminPlugin.getOrCreate(Some("unknown_catalog")) eq defaultPlugin)

    val catalog2Plugin = SparkRangerAdminPlugin.getOrCreate(Some(catalogV2))
    assert(catalog2Plugin.getServiceName === "hive_jenkins_catalog2")
    assert(catalog2Plugin.getAppId === catalogV2)
    assert(SparkRangerAdminPlugin.getOrCreate(Some(catalogV2)) eq catalog2Plugin)
  }

  test("check privileges with Ranger service of each catalog") {
    val sparkCatalogTable = s"$sparkCatalog.$namespace1.$table1"
    val catalog2Table = s"$catalogV2.$namespace1.$table2"
    withCleanTmpResources(Seq(
      (sparkCatalogTable, "table"),
      (s"$sparkCatalog.$namespace1", "database"),
      (catalog2Table, "table"))) {
      doAs(admin, sql(s"CREATE DATABASE IF NOT EXISTS $sparkCatalog.$namespace1"))
      doAs(admin, sql(s"CREATE TABLE IF NOT EXISTS $sparkCatalogTable (key int) USING PARQUET"))
      doAs(admin, sql(s"CREATE DATABASE IF NOT EXISTS $catalogV2.$namespace1"))
      doAs(admin, sql(s"CREATE TABLE IF NOT EXISTS $catalog2Table (key int)"))

      // allowed by the policies in Ranger service `hive_jenkins_catalog2` only
      doAs(catalog2OnlyUser, assert(sql(s"SELECT * FROM $catalog2Table").collect().isEmpty))
      interceptEndsWith[AccessControlException](
        doAs(catalog2OnlyUser, sql(s"SELECT * FROM $sparkCatalogTable").collect()))(
        s"does not have [select] privilege on [$namespace1/$table1/key]")

      // allowed by the policies in Ranger service `hive_jenkins` only
      doAs(bob, assert(sql(s"SELECT * FROM $sparkCatalogTable").collect().isEmpty))
      interceptEndsWith[AccessControlException](
        doAs(bob, sql(s"SELECT * FROM $catalog2Table").collect()))(
        s"does not have [select] privilege on [$namespace1/$table2/key]")

      // SELECT from multiple catalogs
      val joinSql =
        s"SELECT * FROM $sparkCatalogTable a JOIN $catalog2Table b ON a.key = b.key"
      interceptEndsWith[AccessControlException](doAs(bob, sql(joinSql).collect()))(
        s"does not have [select] privilege on [$namespace1/$table2/key]")
      // denied privileges are checked with the Ranger plugin of each catalog in single call
      withSingleCallEnabled {
        interceptEquals[AccessControlException](doAs(bob, sql(joinSql).collect()))(
          s"Permission denied: user [$bob] does not have" +
            s" [select] privilege on [$namespace1/$table2/key]")
      }
    }
  }
}
