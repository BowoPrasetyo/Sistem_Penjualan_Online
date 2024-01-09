<?php

class Affiliator_commision_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get affiliators_commision by id
     */
    function get_affiliator_commision($id = 0)
    {
        return $this->db->where('user_id', $id)->get('affiliators_commision')->row_array();
    }
        
    /*
     * function to add new affiliators_commision
     */
    function add_affiliator_commision($params)
    {
        $this->db->insert('affiliators_commision',$params);
        return true;
    }
    
    /*
     * function to update affiliators_commision
     */
    function update_affiliator_commision($id,$params)
    {
        return $this->db->where('user_id', $id)->update('affiliators_commision',$params);
    }

    function count_affiliator_commision($user = 0)
    {
        return $this->db->where('user_id', $user)->get('affiliators_commision')->num_rows();
    }
  }