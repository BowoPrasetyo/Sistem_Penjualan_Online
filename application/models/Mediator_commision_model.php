<?php

class Mediator_commision_model extends CI_Model
{
	function __construct()
	{
		parent::__construct();
	}
	
	/*
	 * Get provider_commision by id
	 */
	function get_mediator_commision()
	{
		return $this->db->get('mediator_commision')->row_array();
	}
	
	/*
	 * function to add new provider_commision
	 */
	function add_mediator_commision($params)
	{
		$this->db->insert('mediator_commision',$params);
		return true;
	}
	
	/*
	 * function to update provider_commision
	 */
	function update_mediator_commision($id,$params)
	{
		return $this->db->update('mediator_commision',$params);
	}
	
	function count_mediator_commision()
	{
		return $this->db->get('mediator_commision')->num_rows();
	}
}
