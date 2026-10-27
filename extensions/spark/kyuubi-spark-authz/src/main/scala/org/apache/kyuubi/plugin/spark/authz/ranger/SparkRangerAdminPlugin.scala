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

import scala.collection.JavaConverters._
import scala.collection.concurrent.TrieMap
import scala.collection.mutable.{ArrayBuffer, LinkedHashMap}

import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.util.ShutdownHookManager
import org.apache.ranger.plugin.model.RangerServiceDef
import org.apache.ranger.plugin.policyengine.{RangerAccessRequest, RangerAccessResult}
import org.apache.ranger.plugin.service.RangerBasePlugin
import org.slf4j.LoggerFactory

import org.apache.kyuubi.plugin.spark.authz.AccessControlException
import org.apache.kyuubi.plugin.spark.authz.util.AuthZUtils.isRanger21orGreater

object SparkRangerAdminPlugin {
  final private val LOG = LoggerFactory.getLogger(getClass)

  final val serviceType: String = "spark"
  final val defaultAppId: String = "sparkSql"
  final val defaultCatalog: String = "spark_catalog"

  private lazy val defaultBasePlugin: RangerBasePlugin =
    initRangerBasePlugin(serviceName = null, appId = defaultAppId)

  private val catalog2pluginMap = TrieMap.empty[String, RangerBasePlugin]

  def getServiceType: String = serviceType

  def getServiceDef: RangerServiceDef = getOrCreate().getServiceDef

  /** plugin config of the default Ranger plugin */
  def getRangerConf: Configuration = RangerConfigProvider.getRangerConf(defaultBasePlugin)

  def isAccessAllowed(request: AccessRequest): RangerAccessResult =
    getOrCreate(request.getResourceCatalog).isAccessAllowed(request)

  /**
   * For a Spark SQL query, it may contain 0 or more privilege objects to verify, e.g. a typical
   * JOIN operator may have two tables and their columns to verify.
   *
   * This configuration controls whether to verify the privilege objects in single call or
   * to verify them one by one.
   */
  def authorizeInSingleCall: Boolean = getRangerConf.getBoolean(
    s"ranger.plugin.$serviceType.authorize.in.single.call",
    false)

  /**
   * This configuration controls whether to override user's usergroups
   * by the mapping fetched from Ranger's UserStore.
   *
   * It relies on Ranger's UserStore is a feature supported since Ranger 2.1.
   *
   * If true, user bound usergroups will be looked up in in Ranger's UserStore
   * and the usergroups of AccessRequest is overriden.
   *
   * Please make sure configs in Ranger set properly:
   * 1. set `ranger.plugin.spark.enable.implicit.userstore.enricher` to true
   * 2. set cache path for UserStore in `ranger.plugin.hive.policy.cache.dir`
   * 3. at least one condition of policies containing scripts, e.g. {{USER.attr}} in row-filter
   */
  def useUserGroupsFromUserStoreEnabled: Boolean = getRangerConf.getBoolean(
    s"ranger.plugin.$serviceType.use.usergroups.from.userstore.enabled",
    false)

  /**
   * plugin initialization of the default Ranger plugin
   * with cleanup shutdown hook registered
   */
  def initialize(): Unit = {
    defaultBasePlugin
  }

  /**
   * Get or create the Ranger plugin for the catalog name.
   * Falls back to the default plugin for None or `spark_catalog`,
   * or when `ranger.plugin.spark.catalog.<catalog>.service.name` is not configured.
   */
  def getOrCreate(catalog: Option[String] = None): RangerBasePlugin = {
    catalog match {
      case None | Some(`defaultCatalog`) => defaultBasePlugin
      case Some(catalogName) =>
        val serviceName =
          getRangerConf.get(s"ranger.plugin.$serviceType.catalog.$catalogName.service.name")
        if (serviceName == null || serviceName.trim.isEmpty) {
          defaultBasePlugin
        } else {
          catalog2pluginMap.getOrElseUpdate(
            catalogName,
            synchronized {
              catalog2pluginMap.getOrElse(
                catalogName,
                initRangerBasePlugin(serviceName = serviceName, appId = catalogName))
            })
        }
    }
  }

  private def initRangerBasePlugin(serviceName: String, appId: String): RangerBasePlugin = {
    val plugin =
      if (isRanger21orGreater) {
        classOf[RangerBasePlugin]
          .getConstructor(classOf[String], classOf[String], classOf[String])
          .newInstance(serviceType, serviceName, appId)
      } else {
        // Ranger 2.0 and below does not support different service names with the same
        // service type, fallback to the service name in ranger config of the service type
        classOf[RangerBasePlugin]
          .getConstructor(classOf[String], classOf[String])
          .newInstance(serviceType, appId)
      }
    plugin.init()
    registerCleanupShutdownHook(plugin)
    LOG.info(s"initialized ranger plugin, serviceName: ${plugin.getServiceName}, appId: $appId")
    plugin
  }

  /**
   * register shutdown hook for plugin cleanup
   */
  private def registerCleanupShutdownHook(plugin: RangerBasePlugin): Unit = {
    ShutdownHookManager.get().addShutdownHook(
      () => {
        if (plugin != null) {
          LOG.info(s"clean up ranger plugin, appId: ${plugin.getAppId}")
          plugin.cleanup()
          plugin.getAuditProviderFactory.shutdown()
        }
      },
      Integer.MAX_VALUE)
  }

  def getFilterExpr(req: AccessRequest): Option[String] = {
    val result = getOrCreate(req.getResourceCatalog).evalRowFilterPolicies(req, null)
    Option(result)
      .filter(_.isRowFilterEnabled)
      .map(_.getFilterExpr)
      .filter(fe => fe != null && fe.nonEmpty)
  }

  def getMaskingExpr(req: AccessRequest): Option[String] = {
    val col = req.getResource.asInstanceOf[AccessResource].getColumn
    val result = getOrCreate(req.getResourceCatalog).evalDataMaskPolicies(req, null)
    Option(result).filter(_.isMaskEnabled).map { res =>
      if ("MASK_NULL".equalsIgnoreCase(res.getMaskType)) {
        "NULL"
      } else if ("CUSTOM".equalsIgnoreCase(result.getMaskType)) {
        val maskVal = res.getMaskedValue
        if (maskVal == null) {
          "NULL"
        } else {
          s"${maskVal.replace("{col}", col)}"
        }
      } else if (result.getMaskTypeDef != null) {
        result.getMaskTypeDef.getName match {
          case "MASK" => regexp_replace(col)
          case "MASK_SHOW_FIRST_4" =>
            regexp_replace(col, hasLen = true)
          case "MASK_SHOW_LAST_4" =>
            val left = regexp_replace(s"left($col, length($col) - 4)")
            s"concat($left, right($col, 4))"
          case "MASK_HASH" => s"md5(cast($col as string))"
          case "MASK_DATE_SHOW_YEAR" => s"date_trunc('YEAR', $col)"
          case _ => result.getMaskTypeDef.getTransformer match {
              case transformer if transformer != null && transformer.nonEmpty =>
                s"${transformer.replace("{col}", col)}"
              case _ => null
            }
        }
      } else {
        null
      }
    }
  }

  private def regexp_replace(expr: String, hasLen: Boolean = false): String = {
    val pos = if (hasLen) ", 5" else ""
    val upper = s"regexp_replace($expr, '[A-Z]', 'X'$pos)"
    val lower = s"regexp_replace($upper, '[a-z]', 'x'$pos)"
    val digits = s"regexp_replace($lower, '[0-9]', 'n'$pos)"
    val other = s"regexp_replace($digits, '[^A-Za-z0-9]', 'U'$pos)"
    other
  }

  /**
   * batch verifying RangerAccessRequests
   * and throws exception with all disallowed privileges
   * for accessType and resources
   */
  def verify(
      requests: Seq[RangerAccessRequest],
      auditHandler: SparkRangerAuditHandler): Unit = {
    if (requests.nonEmpty) {
      // group requests by the Ranger plugin of their catalogs,
      // and keep the original index to report denied resources in order
      val indices = requests.zipWithIndex
        .groupBy {
          case (req: AccessRequest, _) => getOrCreate(req.getResourceCatalog)
          case _ => getOrCreate()
        }
        .toSeq
        .flatMap { case (plugin, reqsWithIdx) =>
          val results = plugin.isAccessAllowed(reqsWithIdx.map(_._1).asJava, auditHandler)
          if (results == null) {
            Nil
          } else {
            reqsWithIdx.map(_._2).zip(results.asScala).collect {
              case (idx, result) if result != null && !result.getIsAllowed => idx
            }
          }
        }
        .sorted
      if (indices.nonEmpty) {
        val user = requests.head.getUser
        val accessTypeToResource =
          indices.foldLeft(LinkedHashMap.empty[String, ArrayBuffer[String]])((m, idx) => {
            val req = requests(idx)
            val accessType = req.getAccessType
            val resource = req.getResource.getAsString
            m.getOrElseUpdate(accessType, ArrayBuffer.empty[String])
              .append(resource)
            m
          })
        val errorMsg = accessTypeToResource
          .map { case (accessType, resources) =>
            s"[$accessType] ${resources.mkString("privilege on [", ",", "]")}"
          }.mkString(", ")
        throw new AccessControlException(
          s"Permission denied: user [$user] does not have $errorMsg")
      }
    }
  }
}
