<?php

 
class Withdraw_provider_maintenance_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get setting by id
     */
    function get_withdraw_provider_maintenance($id)
    {
        return $this->db->get_where('withdraw_provider_maintenance',array('id'=>$id))->row_array();
    }
        
    /*
     * Get all withdraw_provider_maintenance
     */
    function get_all_withdraw_provider_maintenance()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('withdraw_provider_maintenance')->result_array();
    }
        
    /*
     * function to add new setting
     */
    function add($params)
    {
        $this->db->insert('withdraw_provider_maintenance',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update setting
     */
    function update_setting($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('withdraw_provider_maintenance',$params);
    }

    function update_by_name($name,$value)
    {
        $this->db->where('name',$name);
        return $this->db->update('withdraw_provider_maintenance',[
            'value' => $value
        ]);
    }
    
    /*
     * function to delete setting
     */
    function delete_setting($id)
    {
        return $this->db->delete('withdraw_provider_maintenance',array('id'=>$id));
    }

    function provider($user = null) {
      $this->datatables->select('
          withdraw_provider_maintenance.id,
          withdraw_provider_maintenance.amount,
          withdraw_provider_maintenance.created_at,
      '
      );

      
      $this->datatables->from('withdraw_provider_maintenance');
      $this->datatables->where('withdraw_provider_maintenance.type', 'provider');


      $startDate = $this->input->get('start');
      $endDate = $this->input->get('end');
      
      if($startDate && $endDate) {
          $start = date('Y-m-d', strtotime($startDate)) . ' 00:00';
          $end = date('Y-m-d', strtotime($endDate)) . ' 23:59';
          $this->datatables->where('withdraw_provider_maintenance.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
          $this->datatables->where('withdraw_provider_maintenance.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
      }


      return $this->datatables->generate();
  }

  function maintenance($user = null) {
    $this->datatables->select('
        withdraw_provider_maintenance.id,
        withdraw_provider_maintenance.amount,
        withdraw_provider_maintenance.created_at,
    '
    );

    
    $this->datatables->from('withdraw_provider_maintenance');
    $this->datatables->where('withdraw_provider_maintenance.type', 'maintenance');


    $startDate = $this->input->get('start');
    $endDate = $this->input->get('end');
    
    if($startDate && $endDate) {
        $start = date('Y-m-d', strtotime($startDate)) . ' 00:00';
        $end = date('Y-m-d', strtotime($endDate)) . ' 23:59';
        $this->datatables->where('withdraw_provider_maintenance.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
        $this->datatables->where('withdraw_provider_maintenance.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
    }


    return $this->datatables->generate();
  }

  function leader($user = null) {
    $this->datatables->select('
        withdraw_provider_maintenance.id,
        withdraw_provider_maintenance.amount,
        withdraw_provider_maintenance.created_at,
    '
    );

    
    $this->datatables->from('withdraw_provider_maintenance');
    $this->datatables->where('withdraw_provider_maintenance.type', 'maintenance');


    $startDate = $this->input->get('start');
    $endDate = $this->input->get('end');
    
    if($startDate && $endDate) {
        $start = date('Y-m-d', strtotime($startDate)) . ' 00:00';
        $end = date('Y-m-d', strtotime($endDate)) . ' 23:59';
        $this->datatables->where('withdraw_provider_maintenance.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
        $this->datatables->where('withdraw_provider_maintenance.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
    }


    return $this->datatables->generate();
  }

  function mediator($user = null) {
    $this->datatables->select('
        withdraw_provider_maintenance.id,
        withdraw_provider_maintenance.amount,
        withdraw_provider_maintenance.created_at,
    '
    );

    
    $this->datatables->from('withdraw_provider_maintenance');
    $this->datatables->where('withdraw_provider_maintenance.type', 'mediator');


    $startDate = $this->input->get('start');
    $endDate = $this->input->get('end');
    
    if($startDate && $endDate) {
        $start = date('Y-m-d', strtotime($startDate)) . ' 00:00';
        $end = date('Y-m-d', strtotime($endDate)) . ' 23:59';
        $this->datatables->where('withdraw_provider_maintenance.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
        $this->datatables->where('withdraw_provider_maintenance.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
    }


    return $this->datatables->generate();
  }

  function cs($user = null) {
    $this->datatables->select('
        withdraw_provider_maintenance.id,
        withdraw_provider_maintenance.amount,
        withdraw_provider_maintenance.created_at,
    '
    );

    
    $this->datatables->from('withdraw_provider_maintenance');
    $this->datatables->where('withdraw_provider_maintenance.type', 'cs');


    $startDate = $this->input->get('start');
    $endDate = $this->input->get('end');
    
    if($startDate && $endDate) {
        $start = date('Y-m-d', strtotime($startDate)) . ' 00:00';
        $end = date('Y-m-d', strtotime($endDate)) . ' 23:59';
        $this->datatables->where('withdraw_provider_maintenance.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
        $this->datatables->where('withdraw_provider_maintenance.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
    }


    return $this->datatables->generate();
  }
}
