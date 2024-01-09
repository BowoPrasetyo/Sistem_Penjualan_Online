<?php

class Commision_model extends CI_Model
{
  function __construct()
  {
    parent::__construct();
  }

  public function get_total_commision_affiliator($user = 0)
  {
    $data = $this->db->where('user_id', $user)->get('affiliators_commision')->row();
    return $data ? $data->amount : 0;
  }

  public function get_earning_today($user = 0)
  {
    $start = date('Y-m-d') . ' 00:00';
    $end = date('Y-m-d') . ' 23:59';
    $data = $this->db
      ->select('sum(transaction_details.total_commision_affiliator) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.affiliate_id', $user)
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month($user = 0)
  {
    $start = date('Y') . '-' . date('m') . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m') . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_affiliator) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.affiliate_id', $user)
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_yesterday($user = 0)
  {
    $start = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_affiliator) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.affiliate_id', $user)
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }
  

  public function get_total_commision_maintenance($user = 0)
  {
    $data = $this->db->get('maintenance_commision')->row();
    return $data ? $data->amount : 0;
  }

  public function get_earning_today_maintenance($user = 0)
  {
    $start = date('Y-m-d') . ' 00:00';
    $end = date('Y-m-d') . ' 23:59';
    $data = $this->db
      ->select('sum(transaction_details.total_commision_maintenance) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_maintenance()
  {
    $start = date('Y') . '-' . date('m') . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m') . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_maintenance) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_yesterday_maintenance()
  {
    $start = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_maintenance) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_total_commision_provider()
  {
    $data = $this->db->get('provider_commision')->row();
    return $data ? $data->amount : 0;
  }

  public function get_earning_today_provider()
  {
    $start = date('Y-m-d') . ' 00:00';
    $end = date('Y-m-d') . ' 23:59';
    $data = $this->db
      ->select('sum(transaction_details.total_commision_provider) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_provider()
  {
    $start = date('Y') . '-' . date('m') . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m') . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_provider) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_yesterday_provider()
  {
    $start = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_provider) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }


  public function get_total_commision_leader($user = 0)
  {
    $data = $this->db->where('user_id', $user)->get('leaders_commision')->row();
    return $data ? $data->amount : 0;
  }

  public function get_earning_today_leader($user = 0)
  {
    $start = date('Y-m-d') . ' 00:00';
    $end = date('Y-m-d') . ' 23:59';
    $data = $this->db
      ->select('sum(transaction_details.total_commision_leader) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.affiliate_id', $user)
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_leader($user = 0)
  {
    $start = date('Y') . '-' . date('m') . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m') . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_leader) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.affiliate_id', $user)
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_yesterday_leader($user = 0)
  {
    $start = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_leader) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.affiliate_id', $user)
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }


  public function get_total_commision_mediator()
  {
    $data = $this->db->get('mediator_commision')->row();
    return $data ? $data->amount : 0;
  }

  public function get_earning_today_mediator()
  {
    $start = date('Y-m-d') . ' 00:00';
    $end = date('Y-m-d') . ' 23:59';
    $data = $this->db
      ->select('sum(transaction_details.total_commision_mediator) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_mediator()
  {
    $start = date('Y') . '-' . date('m') . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m') . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_mediator) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_yesterday_mediator()
  {
    $start = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_mediator) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_total_commision_cs()
  {
    $data = $this->db->get('cs_commision')->row();
    return $data ? $data->amount : 0;
  }

  public function get_earning_today_cs()
  {
    $start = date('Y-m-d') . ' 00:00';
    $end = date('Y-m-d') . ' 23:59';
    $data = $this->db
      ->select('sum(transaction_details.total_commision_cs) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_cs()
  {
    $start = date('Y') . '-' . date('m') . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m') . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_cs) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }

  public function get_earning_month_yesterday_cs()
  {
    $start = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "01 00:00";
    $end = date('Y') . '-' . date('m', strtotime("-1 month", strtotime(date('Y-m-d')))) . '-' . "31 23:59";
    $data = $this->db
      ->select('sum(transaction_details.total_commision_cs) as earning_today')
      ->join('transactions', 'transaction_details.transaction_id=transactions.id')
      ->where('transaction_details.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
      ->where('transaction_details.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
      ->where('transactions.is_share_commision', 1)
      ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
      ->get('transaction_details')->row();
    return $data ? $data->earning_today : 0;
  }
  
  public function generate_commision_transaction($id = 0)
  {
    $transaction = $this->Transaction_model->get_transaction_commision($id);

    if($transaction) {
      $this->db->trans_start();
      
      $transactionDetail = $this->Transaction_detail_model->findByTransaction($transaction['id'] ?? 0);
      
        $totalCommisionAffiliator = 0;
        $totalCommisionProvider = 0;
        $totalCommisionMaintenance = 0;
	      $totalCommisionMediator = 0;
	      $totalCommisionLeader = 0;
	      $totalCommisionCs = 0;

        foreach($transactionDetail as $detail) {
          $totalCommisionAffiliator = $totalCommisionAffiliator + $detail->total_commision_affiliator;
          $totalCommisionProvider = $totalCommisionProvider + $detail->total_commision_provider;
          $totalCommisionMaintenance = $totalCommisionMaintenance + $detail->total_commision_maintenance;
	        $totalCommisionMediator = $totalCommisionMediator + $detail->total_commision_mediator;
	        $totalCommisionLeader = $totalCommisionLeader + $detail->total_commision_leader;
	        $totalCommisionCs = $totalCommisionCs + $detail->total_commision_cs;
        }

      // set komisi affiliator
      if($transaction['affiliate_id'] != 0) {
        $countAffiliator = $this->Affiliator_commision_model->get_affiliator_commision($transaction['affiliate_id']);
        
        $getAffiliator = $this->db->where('id',$transaction['affiliate_id'])->get('users')->row();
        
        // set komisi leader
        if($getAffiliator) {
	        $countLeader = $this->Leader_commision_model->get_leader_commision($getAffiliator->leader_id);
	
	        if($countLeader <=0) {
		        $this->Leader_commision_model->add_leader_commision([
			        'user_id' => $getAffiliator->leader_id,
			        'amount' => $totalCommisionLeader
		        ]);
	        } else {
		        $this->db->where('user_id',  $getAffiliator->leader_id);
		        $this->db->set('amount', "amount+$totalCommisionAffiliator", FALSE);
		        $this->db->update('leaders_commision');
	        }
        }

        if($countAffiliator <=0) {
          $this->Affiliator_commision_model->add_affiliator_commision([
            'user_id' => $transaction['affiliate_id'],
            'amount' => $totalCommisionAffiliator
          ]);
        } else {
          $this->db->where('user_id',  $transaction['affiliate_id']);
          $this->db->set('amount', "amount+$totalCommisionAffiliator", FALSE);
          $this->db->update('affiliators_commision');
        }
      }

      // set commisi provider
      $countProvider = $this->Provider_commision_model->get_provider_commision();

      if($countProvider <= 0) {
        $this->Provider_commision_model->add_provider_commision([
          'amount' => $totalCommisionProvider
        ]);
      } else {
        $this->db->set('amount', "amount+$totalCommisionProvider", FALSE);
        $this->db->update('provider_commision');
      }

      // set commisi maintenance
      $countProvider = $this->Maintenance_commision_model->get_maintenance_commision();

      if($countProvider <= 0) {
        $this->Maintenance_commision_model->add_maintenance_commision([
          'amount' => $totalCommisionMaintenance
        ]);
      } else {
        $this->db->set('amount', "amount+$totalCommisionMaintenance", FALSE);
        $this->db->update('maintenance_commision');
      }
	
	    // set commisi mediator
	    $countMediator = $this->Mediator_commision_model->get_mediator_commision();
	
	    if($countMediator <= 0) {
		    $this->Mediator_commision_model->add_mediator_commision([
			    'amount' => $totalCommisionMediator
		    ]);
	    } else {
		    $this->db->set('amount', "amount+$totalCommisionMediator", FALSE);
		    $this->db->update('mediator_commision');
	    }
	
	    // set commisi cs
	    $countCs = $this->Cs_commision_model->get_cs_commision();
	
	    if($countCs <= 0) {
		    $this->Cs_commision_model->add_cs_commision([
			    'amount' => $totalCommisionCs
		    ]);
	    } else {
		    $this->db->set('amount', "amount+$totalCommisionCs", FALSE);
		    $this->db->update('cs_commision');
	    }

      $this->Transaction_model->update_transaction($id, [
        'is_share_commision' => 1
      ]);

      $this->db->trans_complete();
    
      if ($this->db->trans_status() === FALSE) {
        $this->db->trans_rollback();
        return false;
      }else {
        $this->db->trans_commit();
        return true;
      }

    }
  }  
}
