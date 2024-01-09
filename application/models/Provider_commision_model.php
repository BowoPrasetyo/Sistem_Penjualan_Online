<?php

class Provider_commision_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get provider_commision by id
     */
    function get_provider_commision()
    {
        return $this->db->get('provider_commision')->row_array();
    }
        
    /*
     * function to add new provider_commision
     */
    function add_provider_commision($params)
    {
        $this->db->insert('provider_commision',$params);
        return true;
    }
    
    /*
     * function to update provider_commision
     */
    function update_provider_commision($id,$params)
    {
        return $this->db->update('provider_commision',$params);
    }

    function count_provider_commision()
    {
        return $this->db->get('provider_commision')->num_rows();
    }
  }