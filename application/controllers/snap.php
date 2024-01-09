<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Snap extends CI_Controller {
	public function __construct()
    {
      parent::__construct();
      $params = array('server_key' => 'SB-Mid-server-KtVmhxvigdmrtNRZdnQHh8KW', 'production' => false);
			$this->load->library('midtrans');
			$this->midtrans->config($params);
			$this->load->helper('url');	
    }

    public function index()
    {
    	$this->load->view('checkout_snap');
    }

    public function token()
    {
		
			// Required
			$transaction_details = array(
				'order_id' => rand(),
				'gross_amount' => 18000, // no decimal allowed for creditcard
			);

			// Optional
			$item_details = [
				[
					'id' => 'a1',
					'price' => 18000,
					'quantity' => 1,
					'name' => "Apple"
				]
			];

			// Optional
			$billing_address = array(
				'first_name'    => "Andri",
				'last_name'     => "Litani",
				'address'       => "Mangga 20",
				'city'          => "Jakarta",
				'postal_code'   => "16602",
				'phone'         => "081122334455",
				'country_code'  => 'IDN'
			);

			// Optional
			$shipping_address = array(
				'first_name'    => "Obet",
				'last_name'     => "Supriadi",
				'address'       => "Manggis 90",
				'city'          => "Jakarta",
				'postal_code'   => "16601",
				'phone'         => "08113366345",
				'country_code'  => 'IDN'
			);

			// Optional
			$customer_details = array(
				'first_name'    => "Andri",
				'last_name'     => "Litani",
				'email'         => "andri@litani.com",
				'phone'         => "081122334455",
				'billing_address'  => $billing_address,
				'shipping_address' => $shipping_address
			);

			// Data yang akan dikirim untuk request redirect_url.
			$credit_card['secure'] = true;
			//ser save_card true to enable oneclick or 2click
			//$credit_card['save_card'] = true;

			$time = time();
			$custom_expiry = array(
					'start_time' => date("Y-m-d H:i:s O",$time),
					'unit' => 'minute', 
					'duration'  => 2
			);
			
			$transaction_data = array(
					'transaction_details'=> $transaction_details,
					'item_details'       => $item_details,
					'customer_details'   => $customer_details,
					'credit_card'        => $credit_card,
					'expiry'             => $custom_expiry
			);

			error_log(json_encode($transaction_data));
			$snapToken = $this->midtrans->getSnapToken($transaction_data);
			error_log($snapToken);
			echo $snapToken;
    }
}
