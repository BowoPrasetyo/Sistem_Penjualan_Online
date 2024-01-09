<?php
defined('BASEPATH') or exit('No direct script access allowed');
require_once APPPATH . 'core/Backoffice_Controller.php';

class Transaction extends Backoffice_Controller
{
	public function __construct()
	{
		parent::__construct();
		$this->load->model('Transaction_model');
		$this->load->model('Product_model');
		$this->load->model('Transaction_detail_model');
		$this->load->model('Transaction_shipping_model');
		$this->load->model('Affiliator_commision_model');
		$this->load->model('Maintenance_commision_model');
		$this->load->model('Provider_commision_model');
		$this->load->model('Commision_model');
		$this->load->model('Notification_model');
	}

	public function datatable()
	{
		header('Content-Type: application/json');
		echo $this->Transaction_model->datatable_backoffice();
	}

	public function commision()
	{
		header('Content-Type: application/json');
		echo $this->Transaction_model->commision_backoffice(
			$this->input->get('user') ?? 0
		);
	}

	public function index()
	{
		$this->data['page_title'] = 'Transaksi';
		$this->data['page'] = 'backoffice/transaction/index';

		$this->data['breadcrumbs'] = [
			[
				'title' => 'Apps',
				'link' => '#'
			],
			[
				'title' => 'Produk',
				'link' => 1
			]
		];

		$this->load->view('backoffice/index', $this->data);
	}

	function detail($order_id)
	{
		$this->data['detail']['transaction'] = $this->Transaction_model->findByOrderId($order_id);
		$this->data['detail']['product'] = $this->Transaction_detail_model->findByTransaction($this->data['detail']['transaction']->id ?? 0);
		$this->data['detail']['shipping'] = $this->Transaction_shipping_model->findByTransaction($this->data['detail']['transaction']->id ?? 0);

		$this->data['page_title'] = 'Detail Transaksi ' . $order_id;
		$this->data['page'] = 'backoffice/transaction/detail';
		$this->data['breadcrumbs'] = [
			[
				'title' => 'Apps',
				'link' => '#'
			],
			[
				'title' => 'Transaksi',
				'link' => '#'
			],
			[
				'title' => $order_id,
				'link' => '#'
			]
		];
		$this->load->view('backoffice/index', $this->data);
	}

	public function report()
	{
		$this->data['page_title'] = 'Laporan Transaksi';
		$this->data['page'] = 'backoffice/transaction/report';

		$this->data['breadcrumbs'] = [
			[
				'title' => 'Apps',
				'link' => '#'
			],
			[
				'title' => 'Transaksi',
				'link' => ''
			]
		];

		$this->load->view('backoffice/index', $this->data);
	}

	public function downloadlaporantransaksi()
	{
		set_include_path(APPPATH . 'third_party/PHPExcel/Classes/');
		include 'PHPExcel/IOFactory.php';
		$objPHPExcel = new PHPExcel();
		$idtarif = $this->db->query("select a.id as no, c.first_name , 
		c.last_name, c.email, c.phone ,a.order_id , a.amount ,a.item_status,
		 a.created_at,b.quantity,b.delivery_status,d.title from transactions a 
		 join transaction_details b on a.id = b.transaction_id join users c
		 on a.user_id = c.id join products d on b.product_id = d.id")->result_array();
		$data = $idtarif;
		$no = 1;
		$row = 2;
		if (count($data) > 0) {
			if ($data) {
			
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('A1', 'No');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('B1', 'Nama Depan');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('C1', 'Belakang');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('D1', 'Email');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('E1', 'Telephone');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('F1', 'Order Id');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('G1', 'Total Belanja');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('H1', 'Status Pengiriman');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('I1', 'Tanggal Pembuatan');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('J1', 'Nama Barang');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('K1', 'Jumlah Item');

				foreach ($data as $dataExcel) {
	
					$objPHPExcel->getActiveSheet(0)->getStyle('A' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('A' . $row, $dataExcel['no'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('A')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('B' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('B' . $row, $dataExcel['first_name'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('B')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('C' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('C' . $row, $dataExcel['last_name'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('C')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('D' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('D' . $row, $dataExcel['email'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('D')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('E' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('E' . $row, $dataExcel['phone'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('E')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('F' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('F' . $row, $dataExcel['order_id'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('F')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('G' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('G' . $row, $dataExcel['amount'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('G')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('H' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('H' . $row, $dataExcel['item_status'], PHPExcel_Cell_DataType::TYPE_STRING);
					// $objPHPExcel->getActiveSheet(0)->setCellValueExplicit('H' . $row, $dataExcel['delivery_status'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('H')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('I' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('I' . $row, $dataExcel['created_at'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('I')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('J' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('J' . $row, $dataExcel['title'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('J')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('K' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('K' . $row, $dataExcel['quantity'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('K')->setAutoSize(true);

					$row++;
					$no++;
				}
				header('Content-Type: application/vnd.ms-excel; charset=utf-8');
				header('Content-Disposition: attachment; filename=exporttransaksi.xls');
				header('Cache-Control: max-age=0');
				ob_end_clean();
				ob_start();
				$objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, 'Excel5');
				$filename = 'Sample' . 'csv';
				$objWriter->save('php://output');
			}
		}
	}

	public function update_no_receipt($id = 0)
	{
		$this->db->trans_start();

		$value = $this->input->post('value');

		$transaction = $this->Transaction_model->get_transaction($id);

		$this->Transaction_model->update_transaction($id, [
			'no_receipt' => $value,
			'item_status' => 'send'
		]);

		if ($transaction['item_status'] != 'send') {
			$this->Notification_model->add_notification([
				'user_id' => $transaction['user_id'],
				'content' => "Pesanan <strong>{$transaction['order_id']}</strong> Dikirim",
				'created_at' => date('Y-m-d H:i:s'),
				'updated_at' => date('Y-m-d H:i:s'),
			]);
		} else {
			$this->Notification_model->add_notification([
				'user_id' => $transaction['user_id'],
				'content' => "Pesanan <strong>{$transaction['order_id']}</strong> Update Resi",
				'created_at' => date('Y-m-d H:i:s'),
				'updated_at' => date('Y-m-d H:i:s'),
			]);
		}

		$this->db->trans_complete();
		if ($this->db->trans_status() === FALSE) {
			$this->db->trans_rollback();
		} else {
			$this->db->trans_commit();
		}

		// toJson([
		//   'success' => true,
		//   'message' => 'Success',
		//   'data' => $this->Commision_model->generate_commision_transaction($id)
		// ]);
		toJson([
			'success' => true,
			'message' => 'Success',
			'data' => null
		]);
	}

	public function update_status($id = 0)
	{
		$this->db->trans_start();

		$value = $this->input->post('value');

		$this->Transaction_model->update_transaction($id, [
			'item_status' => $value
		]);

		if ($value == 'complete') {
			$this->Commision_model->generate_commision_transaction($id);
		}

		$status = '';

		if ($value == 'process') {
			$status = 'Diproses';
		} else if ($value == 'complete') {
			$status = 'Selesai';
		}

		$transaction = $this->Transaction_model->get_transaction($id);

		$this->Notification_model->add_notification([
			'user_id' => $transaction['user_id'],
			'content' => "Pesanan <strong>{$transaction['order_id']}</strong> $status",
			'created_at' => date('Y-m-d H:i:s'),
			'updated_at' => date('Y-m-d H:i:s'),
		]);

		$this->db->trans_complete();
		if ($this->db->trans_status() === FALSE) {
			$this->db->trans_rollback();
		} else {
			$this->db->trans_commit();
		}

		toJson([
			'success' => true,
			'message' => 'Success',
			'data' => null
		]);
	}

	public function update_cod_price($id = 0)
	{
		$this->db->trans_start();

		$value = $this->input->post('value');

		$this->Transaction_model->update_transaction($id, [
			'cash_on_delivery_markup' => $value
		]);

		$this->db->trans_complete();
		if ($this->db->trans_status() === FALSE) {
			$this->db->trans_rollback();
		} else {
			$this->db->trans_commit();
		}

		toJson([
			'success' => true,
			'message' => 'Success',
			'data' => null
		]);
	}
}
