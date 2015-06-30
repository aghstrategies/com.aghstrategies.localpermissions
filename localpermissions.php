<?php

/**
 * @file
 * Local Permissions extension for CiviCRM.
 *
 * Offers privileges that grant automatic permissions over contacts in a user's
 * state or county.
 *
 * Copyright 2014-2015 AGH Strategies, LLC (email : info@aghstrategies.com)
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

require_once 'localpermissions.civix.php';

/**
 * Create New Permissions.
 */
function localpermissions_civicrm_permission( &$permissions ){
  $prefix = ts('NDI CiviCRM County-State Permissions') . ': ';
  $permissions = array(
    'view county contacts'     => $prefix . ts('view all contacts who live in your county'),
    'edit county contacts'     => $prefix . ts('edit all contacts who live in your county'),
    'delete county contacts'   => $prefix . ts('delete all contacts who live in your county'),
    'view state contacts'      => $prefix . ts('view all contacts who live in your state'),
    'edit state contacts'      => $prefix . ts('edit all contacts who live in your state'),
    'delete state contacts'    => $prefix . ts('delete all contacts who live in your state'),
  ); // NB: note the convention of using delete in ComponentName, plural for edits
}

/**
 * Add permissions to current user and adds primary address to new table.
 */
function localpermissions_civicrm_aclWhereClause($type, &$tables, &$whereTables, &$contactID, &$where) {
  require_once 'CRM/Contact/BAO/Contact/Permission.php';
  if ((CRM_Core_Permission::check('view state contacts') && $type == "1")
      || (CRM_Core_Permission::check('edit state contacts') && $type == "2")
      || (CRM_Core_Permission::check('delete state contacts') && $type == "3")) {
    $address_table = 'civicrm_address';
    $tables[$address_table] = $whereTables[$address_table] = "LEFT JOIN {$address_table} address ON address.contact_id = contact_a.id";
    $where = "address.state_province_id IN
								(SELECT state_province_id FROM civicrm_address WHERE contact_id = {$contactID} AND is_primary = 1 )";
  }
  elseif ((CRM_Core_Permission::check('view county contacts') && $type == "1")
           || (CRM_Core_Permission::check('edit county contacts') && $type == "2")
           || (CRM_Core_Permission::check('delete county contacts') && $type == "3")) {
    $address_table = 'civicrm_address';
    $tables[$address_table] = $whereTables[$address_table] = "LEFT JOIN {$address_table} address ON address.contact_id = contact_a.id";
    $where = "address.county_id IN (SELECT county_id FROM civicrm_address WHERE contact_id = {$contactID} AND is_primary = 1 )";
  }
}

/**
 * Prevents address_id from being overriden, creates address record will NULL id.
 */
function localpermissions_civicrm_postprocess($formName, &$form) {
  if (CRM_Utils_Array::value('address', $form->getVar('_values'))) {
    $contactID = $form->_contactId;
    $settings = CRM_Core_BAO_Setting::getItem("Permission Address");
    $custom_id = $settings["custom_id"];
    $addresses = $form->_values['address'];
    $settings = CRM_Core_BAO_Setting::getItem("Permission Address");
    $submitted = $form->_submitValues["address"];
    $table = "address_permissions";
    foreach ($addresses as $key => $value) {
      foreach ($submitted[$key] as $k => $v) {
        $keys = explode("_", $k);
        if ($keys[0] == "custom" && $keys[1] == $custom_id && $v == 1) {
          $sql  = "SELECT address_id FROM {$table} WHERE contact_id = {$contactID} AND address_id = {$value['id']}";
          $dao = CRM_Core_DAO::executeQuery($sql, CRM_Core_DAO::$_nullArray);
          if (!$dao->fetch()) {
            $insertSql = "INSERT INTO {$table} (contact_id, address_id) VALUES ({$contactID}, {$value['id']})";
            $dao2 = CRM_Core_DAO::executeQuery($insertSql, CRM_Core_DAO::$_nullArray);
          }
        }
        elseif ($keys[0] == "custom" && $keys[1] == $custom_id && $v == 0) {
          $sql  = "SELECT address_id FROM {$table} WHERE contact_id = {$contactID} AND address_id = {$value['id']}";
          $dao = CRM_Core_DAO::executeQuery($sql, CRM_Core_DAO::$_nullArray);
          if ($dao->fetch()) {
            $sql = "DELETE FROM {$table} WHERE address_id = {$value['id']} AND contact_id = {$contactID}";
            $dao = CRM_Core_DAO::executeQuery($sql);
          }
        }
        else {
          $checksql = "SELECT address_id FROM {$table} WHERE address_id = {$value['id']}";
          $checkdao = CRM_Core_DAO::executeQuery($checksql, CRM_Core_DAO::$_nullArray);
          if (!$checkdao->fetch()) {
            $sql = "SELECT id, state_province_id, county_id FROM civicrm_address WHERE id = {$value['id']}";
            $dao = CRM_Core_DAO::executeQuery($sql, CRM_Core_DAO::$_nullArray);
            $dao->fetch();
            if (($dao->id > 0) && (array_key_exists('county_id', $value) && $value['county_id'] == $dao->county_id) && ($value['state_province_id'] == $dao->state_province_id) && (!CRM_Core_Permission::check('edit county contacts') || !CRM_Core_Permission::check('edit all contacts'))) {
              $value['id'] = "NULL";
            }
          }
        }
      } //end foreach
    } //end foreach
  } //end if
}

/**
 * Freeze state and county field is user doesn't have permission to change.
 */
function localpermissions_civicrm_buildform($formName, &$form) {
  if (CRM_Utils_Array::value('address', $form->getVar('_values')) && CRM_Core_Permission::check('edit all contacts') != "1") {
    foreach ($form->_values['address'] as $key => $value) {
      $sql = "SELECT address_id FROM address_permissions WHERE address_id = {$value['id']}";
      $dao = CRM_Core_DAO::executeQuery($sql, CRM_Core_DAO::$_nullArray);
      if ($dao->fetch()) {
        foreach ($form->_elements as $k => $v) {
          if (CRM_Utils_Array::value('name', $v->_attributes)) {
            if (strpos($v->_attributes['name'], "county_id")) {
              $element = $form->_elements[$k];
              $element->_flagFrozen = 1;
            }
            if (strpos($v->_attributes['name'], "state_province_id")) {
              $element = $form->_elements[$k];
              $element->_flagFrozen = 1;
            }
          }
        }
      }
    }
  }
}

/*
 * Implementation of hook_civicrm_config
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_config
 */
function localpermissions_civicrm_config(&$config) {
  _localpermissions_civix_civicrm_config($config);
}

/**
 * Implementation of hook_civicrm_xmlMenu
 *
 * @param $files array(string)
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_xmlMenu
 */
function localpermissions_civicrm_xmlMenu(&$files) {
  _localpermissions_civix_civicrm_xmlMenu($files);
}

/**
 * Implementation of hook_civicrm_install
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_install
 */
function localpermissions_civicrm_install() {
  $sql = 'DROP TABLE IF EXISTS address_permissions';
  $dao = CRM_Core_DAO::executeQuery($sql, CRM_Core_DAO::$_nullArray);
  $sql = 'CREATE TABLE address_permissions ( address_id int, contact_id int );';
  $dao = CRM_Core_DAO::executeQuery($sql, CRM_Core_DAO::$_nullArray);
  $params = array(
    'version' => '3',
    'name' => 'permissioned_address',
    'title' => 'Permissioned Address',
    'extends' => 'Address',
    'style' => 'Inline',
    'collapse_display' => '0',
    'weight' => '3',
    'is_active' => '1',
    'is_multiple' => '0',
  );
  $results = civicrm_api('CustomGroup', 'create', $params);
  $gid = $results['id'];
  $params = array(
    'version' => '3',
    "custom_group_id" => $gid,
    "name" => "is_permissioned",
    "label" => "Is Permissioned",
    "data_type" => "Boolean",
    "html_type" => "Radio",
    "help_post" => "If enabled this contact will have permission over contacts in this graphical region",
    "is_required" => "0",
    "is_searchable" => "1",
    "is_search_range" => "0",
    "weight" => "2",
    "is_active" => "1",
    "is_view" => "0",
    "text_length" => "255",
    "note_columns" => "60",
    "note_rows" => "4",
  );
  $results = civicrm_api('CustomField', 'create', $params);
  $fid = $results["id"];
  CRM_Core_BAO_Setting::setItem($fid, "Permission Address", "custom_id");
  CRM_Core_BAO_Setting::setItem($gid, "Permission Address", "group_id");
  return _localpermissions_civix_civicrm_install();
}

/**
 * Implementation of hook_civicrm_uninstall
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_uninstall
 */
function localpermissions_civicrm_uninstall() {
  $sql = 'DROP TABLE IF EXISTS address_permissions';
  //$dao = CRM_Core_DAO::executeQuery($sql, CRM_Core_DAO::$_nullArray);
  return _localpermissions_civix_civicrm_uninstall();
}

/**
 * Implementation of hook_civicrm_enable
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_enable
 */
function localpermissions_civicrm_enable() {
  return _localpermissions_civix_civicrm_enable();
}

/**
 * Implementation of hook_civicrm_disable
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_disable
 */
function localpermissions_civicrm_disable() {
  return _localpermissions_civix_civicrm_disable();
}

/**
 * Implementation of hook_civicrm_upgrade
 *
 * @param $op string, the type of operation being performed; 'check' or 'enqueue'
 * @param $queue CRM_Queue_Queue, (for 'enqueue') the modifiable list of pending up upgrade tasks
 *
 * @return mixed  based on op. for 'check', returns array(boolean) (TRUE if upgrades are pending)
 *                for 'enqueue', returns void
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_upgrade
 */
function localpermissions_civicrm_upgrade($op, CRM_Queue_Queue $queue = NULL) {
  return _localpermissions_civix_civicrm_upgrade($op, $queue);
}

/**
 * Implementation of hook_civicrm_managed
 *
 * Generate a list of entities to create/deactivate/delete when this module
 * is installed, disabled, uninstalled.
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_managed
 */
function localpermissions_civicrm_managed(&$entities) {
  return _localpermissions_civix_civicrm_managed($entities);
}

/**
 * Implementation of hook_civicrm_caseTypes
 *
 * Generate a list of case-types
 *
 * Note: This hook only runs in CiviCRM 4.4+.
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_caseTypes
 */
function localpermissions_civicrm_caseTypes(&$caseTypes) {
  _localpermissions_civix_civicrm_caseTypes($caseTypes);
}

/**
 * Implementation of hook_civicrm_alterSettingsFolders
 *
 * @link http://wiki.civicrm.org/confluence/display/CRMDOC/hook_civicrm_alterSettingsFolders
 */
function localpermissions_civicrm_alterSettingsFolders(&$metaDataFolders = NULL) {
  _localpermissions_civix_civicrm_alterSettingsFolders($metaDataFolders);
}
