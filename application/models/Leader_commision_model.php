<?php

class Leader_commision_model extends CI_Model
{
	function __construct()
	{
		parent::__construct();
	}
	
	/*
	 * Get affiliators_commision by id
	 */
	function get_leader_commision($id = 0)
	{
		return $this->db->where('user_id', $id)->get('leaders_commision')->row_array();
	}
	
	/*
	 * function to add new affiliators_commision
	 */
	function add_leader_commision($params)
	{
		$this->db->insert('leaders_commision',$params);
		return true;
	}
	
	/*
	 * function to update affiliators_commision
	 */
	function update_leader_commision($id,$params)
	{
		return $this->db->where('user_id', $id)->update('leaders_commision',$params);
	}
	
	function count_leader_commision($user = 0)
	{
		return $this->db->where('user_id', $user)->get('leaders_commision')->num_rows();
	}
}
