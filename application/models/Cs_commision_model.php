<?php


class Cs_commision_model extends CI_Model
{
	function __construct()
	{
		parent::__construct();
	}
	
	/*
	 * Get provider_commision by id
	 */
	function get_cs_commision()
	{
		return $this->db->get('cs_commision')->row_array();
	}
	
	/*
	 * function to add new provider_commision
	 */
	function add_cs_commision($params)
	{
		$this->db->insert('cs_commision', $params);
		return true;
	}
	
	/*
	 * function to update provider_commision
	 */
	function update_cs_commision($id, $params)
	{
		return $this->db->update('cs_commision', $params);
	}
	
	function count_cs_commision()
	{
		return $this->db->get('cs_commision')->num_rows();
	}
}
