// server.dart
import 'dart:convert';
import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';

import 'package:mysql1/mysql1.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:bcrypt/bcrypt.dart';
import 'package:pool/pool.dart';


final jwtSecret = Platform.environment['JWT_SECRET'] ?? 'dev-secret';


/// ---------------- MYSQL POOL (CRITICAL FIX) ----------------
final pool = Pool(6);

Future<T> withPoolConn<T>(Future<T> Function(MySqlConnection conn) action) async {
  return pool.withResource(() async {
    final conn = await MySqlConnection.connect(
      ConnectionSettings(
        host: Platform.environment['DB_HOST']!,
        port: int.parse(Platform.environment['DB_PORT']!),
        user: Platform.environment['DB_USER']!,
        password: Platform.environment['DB_PASSWORD']!,
        db: Platform.environment['DB_NAME']!,
      ),
    );
    try {
      return await action(conn);
    } finally {
      await conn.close();
    }
  });
}


/// ---------------- MYSQL POOL (CRITICAL FIX) ----------------
// final pool = Pool(5); // allow 5 concurrent connections

// Future<T> withPoolConn<T>(Future<T> Function(MySqlConnection conn) action) async {
//   return pool.withResource(() async {
//     final conn = await MySqlConnection.connect(
//       ConnectionSettings(
//         host: 'mysql.railway.internal',
//         port: 3306,
//         user: 'root', 
//         password: 'kdUeMrfecaBwmxWKRCDRDevZkocuigEw',
//         db: 'railway',
//       ),
//     );
//     try {
//       return await action(conn);
//     } finally {
//       await conn.close();
//     }
//   });
// }


/// ---------------- CORS MIDDLEWARE ----------------
Middleware corsHeaders() {
  return createMiddleware(
    responseHandler: (res) => res.change(headers: {
      ...res.headers,
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Origin, Content-Type, Authorization',
    }),
  );
}

Future<void> main() async {
  /// ---------------- VERIFY TOKEN ----------------
  Future<int?> verifyToken(Request req) async {
  final authHeader = req.headers['authorization'];
  if (authHeader == null || !authHeader.startsWith('Bearer ')) return null;

  try {
    final token = authHeader.substring(7);
    final jwt = JWT.verify(token, SecretKey(jwtSecret));

    if (jwt.payload.containsKey('userId')) {
      return int.parse(jwt.payload['userId'].toString());
    }

    if (jwt.payload.containsKey('adminId')) {
      return int.parse(jwt.payload['adminId'].toString());
    }

    return null;
  } catch (e) {
    print("JWT ERROR: $e");
    return null;
  }
}
/// ---------------- VERIFY ADMIN TOKEN ----------------
Future<int?> verifyAdminToken(Request req) async {
  final authHeader = req.headers['authorization'];
  if (authHeader == null || !authHeader.startsWith('Bearer ')) return null;

  try {
    final token = authHeader.substring(7);
    final jwt = JWT.verify(token, SecretKey(jwtSecret));

    if (jwt.payload['role'] == 'admin' &&
        jwt.payload.containsKey('adminId')) {
      return int.parse(jwt.payload['adminId'].toString());
    }

    return null;
  } catch (e) {
    print("ADMIN JWT ERROR: $e");
    return null;
  }
}
  /// ---------------- FILE → BASE64 ----------------
  Future<String> filePathToBase64(String? filePath) async {
    if (filePath == null || filePath.isEmpty) return "";
    try {
      final file = File(filePath);
      if (!await file.exists()) return "";
      return base64Encode(await file.readAsBytes());
    } catch (_) {
      return "";
    }
  }
///
///
  /// ---------------- HANDLER ----------------
  final handler = Pipeline()
      .addMiddleware(corsHeaders())
      .addMiddleware(logRequests())
      .addHandler((Request req) async {
    final path = req.url.path;
    final method = req.method;

/// ================= REGISTER =================
if (path == 'api/auth/register' && method == 'POST') {
  final raw = await req.readAsString();
  final body = jsonDecode(raw);

  final email = body['email']?.toString().trim();
  final password = body['password']?.toString();
  final username = body['username']?.toString().trim();
  final managerId = body['manager_id'];

  if (email == null ||
      password == null ||
      username == null ||
      managerId == null) {
    return Response(
      400,
      body: jsonEncode({"message": "Missing fields"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  final hash = BCrypt.hashpw(password, BCrypt.gensalt());

  return await withPoolConn((conn) async {
    final existing = await conn.query(
      'SELECT id FROM users WHERE email = ?',
      [email],
    );

    if (existing.isNotEmpty) {
      return Response(
        409,
        body: jsonEncode({"message": "Email already exists"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    await conn.query(
      '''
      INSERT INTO users (username, email, password, manager_id)
      VALUES (?, ?, ?, ?)
      ''',
      [username, email, hash, managerId],
    );

    return Response.ok(
      jsonEncode({"ok": true}),
      headers: {"Content-Type": "application/json"},
    );
  });
}


/// ================= GET RECRUITING MANAGERS =================
if (path == 'api/managers' && method == 'GET') {
  return await withPoolConn((conn) async {
    final result = await conn.query(
      '''
      SELECT id, username
      FROM admin_users
      WHERE admin_type = 'RECRUITING_MANAGER'
      '''
    );

    final managers = result.map((row) {
      return {
        "id": row['id'],
        "username": row['username'],
      };
    }).toList();

    return Response.ok(
      jsonEncode(managers),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// ================= ADMIN : TODAY MY TEAM PRESENT USERS =================
if (path == 'api/admin/attendance/today/my-team' && method == 'GET') {

  final authHeader = req.headers['authorization'];
  if (authHeader == null || !authHeader.startsWith('Bearer ')) {
    return Response(401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  try {
    final jwt = JWT.verify(authHeader.substring(7), SecretKey(jwtSecret));

    final adminId = jwt.payload['adminId'];
    final adminType = jwt.payload['admin_type'];

    // Only manager can access
    if (adminType != 'RECRUITING_MANAGER') {
      return Response.ok(
        jsonEncode({"ok": true, "data": []}),
        headers: {"Content-Type": "application/json"},
      );
    }

    //  Read date from query param
    final dateParam = req.url.queryParameters['date'];
    final targetDate = dateParam ??
        DateTime.now().toIso8601String().split('T')[0];

    return await withPoolConn((conn) async {

      final rows = await conn.query(
        '''
        SELECT u.id, u.username, u.email, a.in_time, a.out_time, a.latitude, a.longitude , a.approval_status
        FROM attendance a
        JOIN users u ON u.id = a.user_id
        WHERE DATE(a.in_time) = ?
        AND u.manager_id = ?
        ORDER BY a.in_time ASC
        ''',
        [targetDate, adminId],
      );

      final data = rows.map((r) => {
        "id": r['id'],
        "username": r['username'],
        "email": r['email'],
        "in_time": r['in_time']?.toString(),
        "out_time": r['out_time']?.toString(),
        "lat": r['latitude'],
        "lng": r['longitude'],
        "status": r['approval_status'],
      }).toList();


      return Response.ok(
        jsonEncode({"ok": true, "data": data}),
        headers: {"Content-Type": "application/json"},
      );
    });

  } catch (e) {
    return Response(401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }
}
// ================= ADMIN : LEAVE HISTORY =================
if (path == 'api/admin/leaves/history' && method == 'GET') {
  final auth = req.headers['authorization'];
  if (auth == null || !auth.startsWith('Bearer ')) {
    return Response(401,
        body: jsonEncode({"message": "Invalid token"}),
        headers: {"Content-Type": "application/json"});
  }

  final jwt = JWT.verify(auth.substring(7), SecretKey(jwtSecret));
  final adminId = jwt.payload['adminId'];
  final adminType = jwt.payload['admin_type'];

  return await withPoolConn((conn) async {
    late Results rows;

    if (adminType == 'RECRUITING_MANAGER') {
      rows = await conn.query(
        '''
        SELECT l.*, u.username
        FROM leave_requests l
        JOIN users u ON u.id = l.user_id
        WHERE l.manager_id = ?
        ORDER BY l.created_at DESC
        ''',
        [adminId],
      );
    } else if (adminType == 'HR') {
      rows = await conn.query(
        '''
        SELECT l.*, u.username
        FROM leave_requests l
        JOIN users u ON u.id = l.user_id
        WHERE l.hr_id = ?
        ORDER BY l.created_at DESC
        ''',
        [adminId],
      );
    } else {
      rows = await conn.query('SELECT 1 WHERE 0');
    }

    final data = rows.map((r) => {
          "id": r['id'],
          "employee_name": r['username'],
          "leave_type": r['leave_type'],
          "from_date": r['from_date']?.toString(),
          "to_date": r['to_date']?.toString(),
          "reason": r['reason']?.toString() ?? "",
          "manager_status": r['manager_status'],
          "hr_status": r['hr_status'],
          "status": r['status'],
        }).toList();

    return Response.ok(
      jsonEncode({"ok": true, "data": data}),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// ================= ADMIN LOGIN =================
if (path == 'admin/login' && method == 'POST') {
  final body = jsonDecode(await req.readAsString());
  final username = body['username']; 
  final password = body['password'];
  if (username == null || password == null) {
    return Response(400,
      body: jsonEncode({"message": "Missing credentials"}),
      headers: {"Content-Type": "application/json"},
    );
  }
  return await withPoolConn((conn) async {
    final res = await conn.query(
  'SELECT id, password, admin_type FROM admin_users WHERE username = ?',
  [username],
);

    if (res.isEmpty || !BCrypt.checkpw(password, res.first['password'])) {
      return Response(401,
        body: jsonEncode({"message": "Invalid admin credentials"}),
        headers: {"Content-Type": "application/json"},
      );
    }
    final jwt = JWT({
  "adminId": res.first['id'],
  "role": "admin",
  "admin_type": res.first['admin_type'], 
});

    final token = jwt.sign(SecretKey(jwtSecret));
   return Response.ok(
      jsonEncode({
        "ok": true,
        "data": {  
                  "access_token": token,
                  "role": "admin",
                  "admin_type": res.first['admin_type'],
                },
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
}
// ================= GET ADMINS BY TYPE =================
if (path == 'api/admin/by-type' && method == 'GET') {
  final type = req.url.queryParameters['type'];

  if (type == null) {
    return Response(400,
      body: jsonEncode({"message": "Missing admin type"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  return await withPoolConn((conn) async {
    final rows = await conn.query(
      'SELECT id, username FROM admin_users WHERE admin_type = ?',
      [type],
    );

    final data = rows.map((r) => {
      "id": r['id'],
      "username": r['username'],
    }).toList();

    return Response.ok(
      jsonEncode({"ok": true, "data": data}),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// ================= ADMIN : USER LIST =================
if (path == 'api/admin/users' && method == 'GET') {
  final authHeader = req.headers['authorization'];
  if (authHeader == null || !authHeader.startsWith('Bearer ')) {
    return Response(401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }
  try {
    final token = authHeader.substring(7);
    final jwt = JWT.verify(token, SecretKey(jwtSecret));
    //  Allow only admin
    if (jwt.payload['role'] != 'admin') {
      return Response(403,
        body: jsonEncode({"message": "Admin access only"}),
        headers: {"Content-Type": "application/json"},
      );
    }
    return await withPoolConn((conn) async {
      final rows = await conn.query(
        'SELECT id, username, email FROM users ORDER BY id DESC'
      );
      final data = rows.map((r) => {
        "id": r['id'],
        "username": r['username'],
        "email": r['email'],
      }).toList();
      return Response.ok(
        jsonEncode({"ok": true, "data": data}),
        headers: {"Content-Type": "application/json"},
      );
    });
  } catch (e) {
    return Response(401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }
}
// ---------------- ADMIN SIGNUP ----------------
if (path == 'admin/register' && method == 'POST') {
  final body = jsonDecode(await req.readAsString());
  final username = body['username'];
  final password = body['password'];
   final adminType = body['admin_type']; 

  if (username == null || password == null || adminType == null) {
  return Response(400,
    body: jsonEncode({"message": "Missing credentials"}),
    headers: {"Content-Type": "application/json"},
  );
}

if (adminType != 'HR' && adminType != 'RECRUITING_MANAGER') {
  return Response(400,
    body: jsonEncode({"message": "Invalid admin type"}),
    headers: {"Content-Type": "application/json"},
  );
}
  return await withPoolConn((conn) async {
    // check existing
    final existing = await conn.query(
      'SELECT id FROM admin_users WHERE username = ?',
      [username],
    );

    if (existing.isNotEmpty) {
      return Response(409,
        body: jsonEncode({"message": "Username already exists"}),
        headers: {"Content-Type": "application/json"});
    }

    final hash = BCrypt.hashpw(password, BCrypt.gensalt());

    await conn.query(
  '''
  INSERT INTO admin_users (username, password, admin_type, created_at)
  VALUES (?, ?, ?, NOW())
  ''',
  [username, hash, adminType],
);
    return Response.ok(
      jsonEncode({"ok": true, "message": "Admin registered successfully"}),
      headers: {"Content-Type": "application/json"},
    );
  });
}
//================APPLY LEAVE (USER)============
if (path == 'api/leave/apply' && method == 'POST') {
  final userId = await verifyToken(req);
  if (userId == null) return Response(401, body: jsonEncode({"message":"Invalid token"}), headers: {"Content-Type":"application/json"});

  final data = jsonDecode(await req.readAsString());

  final managerId = data['manager_id'];
  final hrId = data['hr_id'];

  if(managerId == null || hrId == null) {
    return Response(400, body: jsonEncode({"message":"Select both manager and HR"}), headers: {"Content-Type":"application/json"});
  }

  return await withPoolConn((conn) async {
    await conn.query(
      '''
      INSERT INTO leave_requests 
      (user_id, leave_type, from_date, to_date, half_day, reason, manager_id, hr_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ''',
      [
        userId,
        data['leave_type'],
        data['from_date'],
        data['to_date'],
        data['half_day'] ?? false,
        data['reason'],
        managerId,
        hrId,
      ],
    );

    return Response.ok(
      jsonEncode({"ok": true, "message": "Leave sent to Manager for approval"}), 
      headers: {"Content-Type":"application/json"},
    );
  });
}
// ================= USER ATTENDANCE VIA LEAVE REQUESTS =================
if (path == 'api/attendance/status-leave' && method == 'GET') {
  final adminId = await verifyToken(req);

  if (adminId == null) {
    return Response(401,
        body: jsonEncode({"message": "Invalid token"}),
        headers: {"Content-Type": "application/json"});
  }

  return await withPoolConn((conn) async {
    final rows = await conn.query(
      '''
      SELECT lr.id, lr.user_id, u.username, lr.leave_type,
             lr.from_date, lr.to_date,
             CAST(lr.reason AS CHAR) AS reason
      FROM leave_requests lr
      JOIN users u ON u.id = lr.user_id
      WHERE (lr.manager_id = ? OR lr.hr_id = ?)
        AND lr.status = 'Approved'
      ORDER BY lr.from_date DESC
      ''',
      [adminId, adminId],
    );

    final List<Map<String, dynamic>> data = [];

    for (var r in rows) {
      DateTime start = r['from_date'];
      DateTime end = r['to_date'];

      for (var d = start; !d.isAfter(end); d = d.add(const Duration(days: 1))) {
        data.add({
          "id": r['id'],
          "user_id": r['user_id'],
          "username": r['username'],
          "leave_type": r['leave_type'],
          "from_date": start.toIso8601String().split('T')[0],
          "to_date": end.toIso8601String().split('T')[0],
          "date": d.toIso8601String().split('T')[0],
          "reason": r['reason'] ?? "",
          "status": "On Leave"
        });
      }
    }

    return Response.ok(
      jsonEncode({"ok": true, "data": data}),
      headers: {"Content-Type": "application/json"},
    );
  });
}

//=================MY LEAVE STATUS (USER)=================
if (path == 'api/leave/my' && method == 'GET') {
  final userId = await verifyToken(req);
  if (userId == null) return Response.forbidden("Invalid token");

  return await withPoolConn((conn) async {
   final rows = await conn.query(
  'SELECT id, leave_type, from_date, to_date, reason, status FROM leave_requests WHERE user_id = ?',
  [userId],
);

final data = rows.map((r) => {
  "id": r['id'],
  "leave_type": r['leave_type'],
  "from_date": r['from_date']?.toString(),
  "to_date": r['to_date']?.toString(),
  "reason": r['reason'] is Blob
      ? utf8.decode((r['reason'] as Blob).toBytes())
      : r['reason']?.toString() ?? "",
  "status": r['status'],
}).toList();


return Response.ok(
  jsonEncode({
    "ok": true,
    "data": data,  
  }),
  headers: {"Content-Type": "application/json"},
);

  });
}

// ================= DELETE LEAVE (USER) =================
if (path.startsWith('leaves/') && method == 'DELETE') {
  final userId = await verifyToken(req);
  if (userId == null) {
    return Response(401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  final leaveId = int.tryParse(path.split('/').last);
  if (leaveId == null) {
    return Response(400,
      body: jsonEncode({"message": "Invalid leave id"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  return await withPoolConn((conn) async {
    final result = await conn.query(
      'DELETE FROM leave_requests WHERE id = ? AND user_id = ?',
      [leaveId, userId],
    );

    return Response.ok(
      jsonEncode({"ok": true}),
      headers: {"Content-Type": "application/json"},
    );
  });
}

//=====================ADMIN – VIEW MY LEAVES ONLY=======================
if (path == 'api/admin/leaves' && method == 'GET') {
  final auth = req.headers['authorization'];
  if (auth == null || !auth.startsWith('Bearer ')) {
    return Response(401, body: jsonEncode({"message": "Invalid token"}), headers: {"Content-Type":"application/json"});
  }

  final jwt = JWT.verify(auth.substring(7), SecretKey(jwtSecret));
  final adminId = jwt.payload['adminId'];
  final adminType = jwt.payload['admin_type']; 

  return await withPoolConn((conn) async {
    late Results rows;

    if (adminType == 'RECRUITING_MANAGER') {
      // Manager: see leaves assigned to them and still pending manager approval
      rows = await conn.query(
        '''
        SELECT 
          l.id,
          u.username,
          l.leave_type,
          l.from_date,
          l.to_date,
          l.reason,
          l.manager_status,
          l.hr_status,
          l.status
        FROM leave_requests l
        JOIN users u ON l.user_id = u.id
        WHERE l.manager_id = ? AND l.manager_status = 'pending'
        ORDER BY l.created_at DESC
        ''',
        [adminId],
      );
    } else if (adminType == 'HR') {
      // HR: see leaves approved by manager but pending HR approval
      rows = await conn.query(
        '''
        SELECT 
          l.id,
          u.username,
          l.leave_type,
          l.from_date,
          l.to_date,
          l.reason,
          l.manager_status,
          l.hr_status,
          l.status
        FROM leave_requests l
        JOIN users u ON l.user_id = u.id
        WHERE l.hr_id = ? AND l.manager_status = 'approved' AND l.hr_status = 'pending'
        ORDER BY l.created_at DESC
        ''',
        [adminId],
      );
    } else {
      // Other admin types: return empty
      rows = await conn.query(
        'SELECT 1 WHERE 0' 
      );
    }

    final data = rows.map((r) => {
      "id": r['id'],
      "employee_name": r['username'],
      "leave_type": r['leave_type'],
      "from_date": r['from_date']?.toString(),
      "to_date": r['to_date']?.toString(),
      "reason": r['reason']?.toString() ?? "",
      "manager_status": r['manager_status'],
      "hr_status": r['hr_status'],
      "status": r['status'],
    }).toList();

    return Response.ok(
      jsonEncode({"ok": true, "data": data}),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// ================= MANAGER – VIEW PENDING LEAVES =================
if (path == 'api/manager/leaves' && method == 'GET') {
  final auth = req.headers['authorization'];
  if (auth == null || !auth.startsWith('Bearer ')) {
    return Response(401, body: jsonEncode({"message": "Invalid token"}), headers: {"Content-Type":"application/json"});
  }

  final jwt = JWT.verify(auth.substring(7), SecretKey(jwtSecret));
  final managerId = jwt.payload['adminId'];

  return await withPoolConn((conn) async {
    final rows = await conn.query(
      '''
      SELECT lr.*, u.username AS employee_name
      FROM leave_requests lr
      JOIN users u ON u.id = lr.user_id
      WHERE lr.manager_id = ?
        AND lr.manager_status = 'pending'
      ORDER BY lr.created_at DESC
      ''',
      [managerId],
    );

    final data = rows.map((r) => {
      "id": r['id'],
      "employee_name": r['employee_name'],
      "leave_type": r['leave_type'],
      "from_date": r['from_date']?.toString(),
      "to_date": r['to_date']?.toString(),
      "reason": r['reason']?.toString() ?? "",
      "manager_status": r['manager_status'],
      "hr_status": r['hr_status'],
    }).toList();

    return Response.ok(
      jsonEncode({"ok": true, "data": data}),
      headers: {"Content-Type": "application/json"},
    );
  });
}
// ================= HR – VIEW APPROVED BY MANAGER =================
if (path == 'api/hr/leaves' && method == 'GET') {
  final auth = req.headers['authorization'];
  final jwt = JWT.verify(auth!.substring(7), SecretKey(jwtSecret));

  final hrId = jwt.payload['adminId'];

  return await withPoolConn((conn) async {
    final rows = await conn.query(
      '''
      SELECT lr.*, u.username AS employee_name
      FROM leave_requests lr
      JOIN users u ON u.id = lr.user_id
      WHERE lr.hr_id = ?
        AND lr.manager_status = 'approved'
        AND lr.hr_status = 'pending'
      ORDER BY lr.created_at DESC
      ''',
      [hrId],
    );

    final data = rows.map((r) => {
      "id": r['id'],
      "employee_name": r['employee_name'],
      "leave_type": r['leave_type'],
      "from_date": r['from_date']?.toString(),
      "to_date": r['to_date']?.toString(),
      "reason": r['reason']?.toString() ?? "",
    }).toList();

    return Response.ok(
      jsonEncode({"ok": true, "data": data}),
      headers: {"Content-Type": "application/json"},
    );
  });
}
//=================== LEAVE BALANCE (USER) =================
if (path == 'api/leave/balance' && method == 'GET') {
  final userId = await verifyToken(req);

  if (userId == null) {
    return Response(401,
        body: jsonEncode({"message": "Invalid token"}),
        headers: {"Content-Type": "application/json"});
  }

  return await withPoolConn((conn) async {
    final rows = await conn.query(
      'SELECT total_leave, used_leave FROM leave_balance WHERE user_id=?',
      [userId],
    );

    int totalLeave;
    int usedLeave;

    if (rows.isEmpty) {
      // Set default total leave to 15 instead of 12
      await conn.query(
        'INSERT INTO leave_balance (user_id,total_leave,used_leave) VALUES (?,?,?)',
        [userId, 15, 0],
      );
      totalLeave = 15;
      usedLeave = 0;
      print('DEBUG: Created default leave balance (15) for userId=$userId');
    } else {
      totalLeave = (rows.first['total_leave'] as num).toInt();
      usedLeave = (rows.first['used_leave'] as num).toInt();
      print('DEBUG: Fetched leave balance total=$totalLeave, used=$usedLeave');
    }

    return Response.ok(
      jsonEncode({
        "total": totalLeave,
        "used": usedLeave,
        "remaining": totalLeave - usedLeave,
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// ================= ADMIN – APPROVE / REJECT LEAVE =================
if (path == 'api/admin/leave/update' && method == 'POST') {
  final auth = req.headers['authorization'];
  final jwt = JWT.verify(auth!.substring(7), SecretKey(jwtSecret));

  if (jwt.payload['role'] != 'admin') {
    return Response.forbidden("Admin only");
  }

  final body = jsonDecode(await req.readAsString());
  final leaveId = body['leave_id'];
  final statusInput = body['status']?.toString().toLowerCase(); // "approved" or "rejected"

  if (statusInput != 'approved' && statusInput != 'rejected') {
    return Response(400,
      body: jsonEncode({"message": "Invalid status"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  return await withPoolConn((conn) async {
    final leave = await conn.query(
      'SELECT manager_id, hr_id, manager_status, hr_status FROM leave_requests WHERE id=?',
      [leaveId],
    );

    if (leave.isEmpty) {
      return Response(
        404,
        body: jsonEncode({"message": "Leave not found"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    final row = leave.first;
    final adminId = jwt.payload['adminId'];

    // ================= MANAGER DECISION =================
    if (adminId == row['manager_id']) {
      if (statusInput == 'rejected') {
        // Manager rejected → final reject immediately
        await conn.query(
          'UPDATE leave_requests SET manager_status=?, status=? WHERE id=?',
          ['rejected', 'Rejected', leaveId],
        );
        return Response.ok(
          jsonEncode({"ok": true, "message": "Leave rejected by manager"}),
          headers: {"Content-Type": "application/json"},
        );
      } else {
        // Manager approved → update manager_status only
        await conn.query(
          'UPDATE leave_requests SET manager_status=? WHERE id=?',
          ['approved', leaveId],
        );
        return Response.ok(
          jsonEncode({"ok": true, "message": "Manager approved leave, waiting for HR"}),
          headers: {"Content-Type": "application/json"},
        );
      }
    }
    // ================= HR DECISION =================
    else if (adminId == row['hr_id'] && row['manager_status'] == 'approved') {

      //  Get user_id of employee
      final userRow = await conn.query(
        'SELECT user_id, status FROM leave_requests WHERE id=?',
        [leaveId],
      );

      final oldStatus = userRow.first['status'];
      final employeeUserId = userRow.first['user_id'];

      String finalStatus = statusInput == 'approved' ? 'Approved' : 'Rejected';

      //  Update leave request
      await conn.query(
        'UPDATE leave_requests SET hr_status=?, status=? WHERE id=?',
        [statusInput, finalStatus, leaveId],
      );

      //  Increase leave balance ONLY if newly approved
      if (oldStatus != 'Approved' && finalStatus == 'Approved') {
        await conn.query(
          'UPDATE leave_balance SET used_leave = used_leave + 1 WHERE user_id=?',
          [employeeUserId],
        );
      }

      return Response.ok(
        jsonEncode({"ok": true, "message": "HR decision recorded, final status updated"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    // ================= NOT ALLOWED =================
    else {
      return Response(
        403,
        body: jsonEncode({
          "message": "Not authorized or manager has not approved yet"
        }),
        headers: {"Content-Type": "application/json"},
      );
    }
  });
}

    /// ================= LOGIN =================
   if (path == 'api/auth/login' && method == 'POST') {
  final body = jsonDecode(await req.readAsString());

  return await withPoolConn((conn) async {
    final res = await conn.query(
      'SELECT id,password,username FROM users WHERE email=?',
      [body['email']],
    );

    if (res.isEmpty ||
        !BCrypt.checkpw(body['password'], res.first['password'])) {
      return Response(401,
        body: jsonEncode({"message": "Invalid credentials"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    final jwt = JWT({"userId": res.first['id']});
    final token = jwt.sign(SecretKey(jwtSecret));

    return Response.ok(
      jsonEncode({
        "access_token": token,
        "username": res.first['username'],
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
}

    // ---------------- ATTENDANCE SUBMIT ----------------
    if (path == 'api/attendance/submit' && method == 'POST') {
  final userId = await verifyToken(req);
  if (userId == null) {
    return Response(401,
        body: jsonEncode({"message": "Invalid token"}),
        headers: {"Content-Type": "application/json"});
  }
  final raw = await req.readAsString();
  final data = jsonDecode(raw);
  return await withPoolConn((conn) async {
    
    final lat = data['lat'];
    final lng = data['lng'];
    final imageBase64 = data['image'];

    String? savedFilePath;

    if (imageBase64 != null && imageBase64.isNotEmpty) {
      final pure = imageBase64.contains(',')
          ? imageBase64.split(',').last
          : imageBase64;

      final bytes = base64Decode(pure);
      final dir = Directory.current.path + "/attendance_images";
      await Directory(dir).create(recursive: true);

      savedFilePath =
          "$dir/att_${userId}_${DateTime.now().millisecondsSinceEpoch}.jpg";
      await File(savedFilePath).writeAsBytes(bytes);
    }

    final today = await conn.query(
      'SELECT id,in_time,out_time FROM attendance WHERE user_id=? AND DATE(created_at)=CURDATE() LIMIT 1',
      [userId],
    );

    if (today.isEmpty) {
      await conn.query(
        'INSERT INTO attendance (user_id, latitude, longitude, image_path, in_time, created_at, approval_status)VALUES (?, ?, ?, ?, NOW(), NOW(), "pending")',
        [userId, lat, lng, savedFilePath],
      );

      return Response.ok(
        jsonEncode({"ok": true, "message": "Checked IN successfully"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    final row = today.first;
    if (row['out_time'] != null) {
      return Response(400,
          body: jsonEncode({"message": "Attendance already completed"}),
          headers: {"Content-Type": "application/json"});
    }

    await conn.query(
      'UPDATE attendance SET out_time=NOW(), latitude=?, longitude=?, image_path=? WHERE id=?',
      [lat, lng, savedFilePath, row['id']],
    );

    return Response.ok(
      jsonEncode({"ok": true, "message": "Checked OUT successfully"}),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// ---------------- ATTENDANCE STATUS (SHOW LEAVE REQUESTS) ----------------
if (path == 'api/attendance/status' && method == 'GET') {
  final userId = await verifyToken(req);
  if (userId == null) {
    return Response(401,
        body: jsonEncode({"message": "Invalid token"}),
        headers: {"Content-Type": "application/json"});
  }

  return await withPoolConn((conn) async {
    final rows = await conn.query(
      'SELECT id, leave_type, from_date, to_date, reason, status FROM leave_requests WHERE user_id = ? ORDER BY id DESC',
      [userId],
    );

    final data = rows.map((r) => {
      "id": r['id'],
      "leave_type": r['leave_type'],
      "from_date": r['from_date']?.toString(),
      "to_date": r['to_date']?.toString(),
      "reason": r['reason'] is Blob
          ? utf8.decode((r['reason'] as Blob).toBytes())
          : r['reason']?.toString() ?? "",
      "status": r['status'], // Approved / Rejected / Pending
    }).toList();

    return Response.ok(
      jsonEncode({
        "ok": true,
        "data": data,
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
}

    // ---------------- UPDATE FACE IMAGE ONLY ----------------
   if (path == 'api/profile/update-face' && method == 'POST') {
  final userId = await verifyToken(req);
  if (userId == null) {
    return Response.forbidden(
      jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  final raw = await req.readAsString();
  final data = jsonDecode(raw);
  final base64Image = data['profile_image'];

  return await withPoolConn((conn) async {
    final bytes = base64Decode(
      base64Image.contains(',')
          ? base64Image.split(',').last
          : base64Image,
    );

    final dir = '${Directory.current.path}/profile_images';
    await Directory(dir).create(recursive: true);

    final filePath =
        '$dir/profile_${DateTime.now().millisecondsSinceEpoch}.jpg';

    await File(filePath).writeAsBytes(bytes);

    await conn.query(
      'UPDATE users SET profile_image=? WHERE id=?',
      [filePath, userId],
    );

    return Response.ok(
      jsonEncode({"ok": true, "image": base64Encode(bytes)}),
      headers: {"Content-Type": "application/json"},
    );
  });
}
//---------------- ADMIN : UPDATE ATTENDANCE STATUS ----------------
if (path == 'api/admin/attendance/update-status' && method == 'POST') {
  final auth = req.headers['authorization'];
  final jwt = JWT.verify(auth!.substring(7), SecretKey(jwtSecret));

  if (jwt.payload['role'] != 'admin') {
    return Response.forbidden("Admin only");
  }

  final body = jsonDecode(await req.readAsString());
  final attendanceId = body['attendance_id'];
  final status = body['status'];

  return await withPoolConn((conn) async {
    await conn.query(
      '''
      UPDATE attendance 
      SET approval_status=?, approved_by=?, approved_at=NOW()
      WHERE id=?
      ''',
      [status, jwt.payload['adminId'], attendanceId],
    );

    return Response.ok(jsonEncode({
      "ok": true,
      "message": "Attendance $status"
    }));
  });
}

    // ---------------- GET PROFILE ----------------
   if (path == 'api/users/profile' && method == 'GET') {
  final userId = await verifyToken(req);
  if (userId == null) {
    return Response(401,
        body: jsonEncode({"message": "Invalid token"}),
        headers: {"Content-Type": "application/json"});
  }

  return await withPoolConn((conn) async {
    final result = await conn.query(
      'SELECT username,email,profile_image FROM users WHERE id=?',
      [userId],
    );

    if (result.isEmpty) {
      return Response.notFound(
        jsonEncode({"message": "User not found"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    final row = result.first;
    final img = await filePathToBase64(row['profile_image']);

    return Response.ok(
      jsonEncode({
        "ok": true,
        "username": row['username'] ?? "",
        "email": row['email'],
        "profile_image": img
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
} 
//
if (path == 'api/admin/profile' && method == 'GET') {
  final adminId = await verifyAdminToken(req);
  if (adminId == null) {
    return Response(
      401,
      body: jsonEncode({"ok": false, "message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  return await withPoolConn((conn) async {
    final result = await conn.query(
      'SELECT username, admin_type FROM admin_users WHERE id = ?',
      [adminId],
    );

    if (result.isEmpty) {
      return Response.notFound(
        jsonEncode({"ok": false, "message": "Admin not found"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    final row = result.first;

    return Response.ok(
      jsonEncode({
        "ok": true,
        "username": row['username'],
        "admin_type": row['admin_type'],
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// =================   : TODAY PRESENT USERS =================
if (path == 'api/admin/attendance/today/users' && method == 'GET') {
  final authHeader = req.headers['authorization'];
  if (authHeader == null || !authHeader.startsWith('Bearer ')) {
    return Response(401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  try {
    final token = authHeader.substring(7);
    final jwt = JWT.verify(token, SecretKey(jwtSecret));

    if (jwt.payload['role'] != 'admin') {
      return Response(403,
        body: jsonEncode({"message": "Admin only"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    return await withPoolConn((conn) async {
      final rows = await conn.query(
        '''
       SELECT DISTINCT 
        u.id,
        u.username,
        u.email,
        a.in_time,
        a.out_time,
        a.latitude,
        a.longitude,
        a.approval_status
      FROM attendance a
      JOIN users u ON u.id = a.user_id
      WHERE DATE(a.in_time) = CURDATE()
      ORDER BY a.in_time ASC

        '''
      );

      final data = rows.map((r) => {
        "id": r['id'],
        "username": r['username'],
        "email": r['email'],
        "in_time": r['in_time']?.toString(),
        "out_time": r['out_time']?.toString(),
        "lat": r['latitude'],
        "lng": r['longitude'],
        "status": r['approval_status'],  
      }).toList();


      return Response.ok(
        jsonEncode({"ok": true, "data": data}),
        headers: {"Content-Type": "application/json"},
      );
    });
  } catch (e) {
    return Response(401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }
}
// ================= ADMIN : TODAY ATTENDANCE COUNT =================
if (path == 'api/admin/attendance/today' && method == 'GET') {

  final authHeader = req.headers['authorization'];
  if (authHeader == null || !authHeader.startsWith('Bearer ')) {
    return Response(
      401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  late JWT jwt;
  try {
    jwt = JWT.verify(authHeader.substring(7), SecretKey(jwtSecret));
  } catch (e) {
    return Response(
      401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  if (jwt.payload['role'] != 'admin') {
    return Response(
      403,
      body: jsonEncode({"message": "Admin only"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  return await withPoolConn((conn) async {

    //  total employees
    final totalRes = await conn.query(
      'SELECT COUNT(*) AS total FROM users'
    );

    //  present today
    final presentRes = await conn.query(
      '''
      SELECT COUNT(DISTINCT user_id) AS presentToday
      FROM attendance
      WHERE DATE(in_time) = CURDATE()
      '''
    );

    //  leave today (APPROVED only)
    final leaveRes = await conn.query(
      '''
      SELECT COUNT(DISTINCT user_id) AS leaveToday
      FROM leave_requests
      WHERE status = 'Approved'
        AND from_date <= CURDATE()
        AND to_date >= CURDATE()
      '''
    );

    final int totalEmployees =
        (totalRes.first['total'] as num).toInt();

    final int presentToday =
        (presentRes.first['presentToday'] as num).toInt();

    final int leaveToday =
        (leaveRes.first['leaveToday'] as num).toInt();

    final int absentToday =
        totalEmployees - presentToday - leaveToday;

    print("TOTAL USERS = $totalEmployees");
    print("PRESENT TODAY = $presentToday");
    print("LEAVE TODAY = $leaveToday");
    print("ABSENT TODAY = $absentToday");

    return Response.ok(
      jsonEncode({
        "ok": true,
        "data": {
          "totalEmployees": totalEmployees,
          "presentToday": presentToday,
          "leaveToday": leaveToday,   
          "absentToday": absentToday
        }
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// ================= RESET PASSWORD =================
if (path == 'api/user/reset-password' && method == 'POST') {
  final userId = await verifyToken(req);
  if (userId == null) {
    return Response(401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  final body = jsonDecode(await req.readAsString());
  final newPassword = body['new_password'];

  if (newPassword == null || newPassword.toString().length < 6) {
    return Response(400,
      body: jsonEncode({"message": "Password too short"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  final hashed = BCrypt.hashpw(
    newPassword.toString(),
    BCrypt.gensalt(),
  );

  return await withPoolConn((conn) async {
    await conn.query(
      'UPDATE users SET password=? WHERE id=?',
      [hashed, userId],
    );

    return Response.ok(
      jsonEncode({"ok": true, "message": "Password updated"}),
      headers: {"Content-Type": "application/json"},
    );
  });
}
//----------------- ADMIN RESET PASSWORD ----------------
if (path == 'api/admin/reset-password' && method == 'POST') {
  final adminId = await verifyAdminToken(req); 
  if (adminId == null) {
    return Response(401,
      body: jsonEncode({"message": "Invalid admin token"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  final body = jsonDecode(await req.readAsString());
  final newPassword = body['new_password'];

  if (newPassword == null || newPassword.toString().length < 6) {
    return Response(400,
      body: jsonEncode({"message": "Password too short"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  final hashed = BCrypt.hashpw(
    newPassword.toString(),
    BCrypt.gensalt(),
  );

  return await withPoolConn((conn) async {
    final result = await conn.query(
      'UPDATE admin_users SET password=? WHERE id=?',
      [hashed, adminId],
    );

    if (result.affectedRows == 0) {
      return Response(400,
        body: jsonEncode({"message": "Admin not found"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    return Response.ok(
      jsonEncode({"ok": true, "message": "Admin password updated"}),
      headers: {"Content-Type": "application/json"},
    );
  });
}

// ---------------- UPDATE PROFILE ----------------
if (path == 'api/user/update-profile' && method == 'POST') {

  final userId = await verifyToken(req);
  if (userId == null) {
    return Response(
      401,
      body: jsonEncode({"message": "Invalid token"}),
      headers: {"Content-Type": "application/json"},
    );
  }
  final rawBody = await req.readAsString();
  if (rawBody.isEmpty) {
    return Response(
      400,
      body: jsonEncode({"message": "Empty request body"}),
      headers: {"Content-Type": "application/json"},
    );
  }

  final data = jsonDecode(rawBody);
  final username = data['username']?.toString().trim() ?? "";
  final imageBase64 = data['profile_image'];

  return await withPoolConn((conn) async {
    String? savedFilePath;
    if (imageBase64 != null && imageBase64.toString().isNotEmpty) {
      final pureBase64 = imageBase64.toString().contains(',')
          ? imageBase64.toString().split(',').last
          : imageBase64.toString();

      final bytes = base64Decode(pureBase64);

      final dir = '${Directory.current.path}/profile_images';
      await Directory(dir).create(recursive: true);

      savedFilePath =
          '$dir/profile_${userId}_${DateTime.now().millisecondsSinceEpoch}.jpg';

      await File(savedFilePath).writeAsBytes(bytes);

      // update username + image
      await conn.query(
        'UPDATE users SET username = ?, profile_image = ? WHERE id = ?',
        [username, savedFilePath, userId],
      );
    } else {
      // update username only
      await conn.query(
        'UPDATE users SET username = ? WHERE id = ?',
        [username, userId],
      );
    }

    // Convert saved image back to Base64 for response
    final profileImageBase64 =
        savedFilePath != null ? await filePathToBase64(savedFilePath) : "";

    return Response.ok(
      jsonEncode({
        "ok": true,
        "message": "Profile updated successfully",
        "username": username,
        "profile_image": profileImageBase64,
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
}
//================== ADMIN : ATTENDANCE BY DATE USERS =================
if (path == 'api/admin/attendance/by-date/users' && method == 'GET') {
  final date = req.url.queryParameters['date'];

  return await withPoolConn((conn) async {
    final rows = await conn.query(
      '''
      SELECT u.id, u.username, u.email, a.in_time, a.out_time, a.latitude, a.longitude, a.approval_status
      FROM attendance a
      JOIN users u ON u.id = a.user_id
      WHERE DATE(a.in_time) = ?
      ORDER BY a.in_time ASC
      ''',
      [date],
    );

    final data = rows.map((r) => {
      "id": r['id'],
      "username": r['username'],
      "email": r['email'],
      "in_time": r['in_time']?.toString(),
      "out_time": r['out_time']?.toString(),
      "lat": r['latitude'],
      "lng": r['longitude'],
      "status": r['approval_status'],
    }).toList();


    return Response.ok(jsonEncode({"ok": true, "data": data}),
        headers: {"Content-Type": "application/json"});
  });
}

//================== ADMIN : ATTENDANCE BY DATE =================
if (path == 'api/admin/attendance/by-date' && method == 'GET') {

  final authHeader = req.headers['authorization'];
  if (authHeader == null || !authHeader.startsWith('Bearer ')) {
    return Response(401, body: jsonEncode({"message": "Invalid token"}));
  }

  late JWT jwt;
  try {
    jwt = JWT.verify(authHeader.substring(7), SecretKey(jwtSecret));
  } catch (e) {
    return Response(401, body: jsonEncode({"message": "Invalid token"}));
  }

  if (jwt.payload['role'] != 'admin') {
    return Response(403, body: jsonEncode({"message": "Admin only"}));
  }

  final date = req.url.queryParameters['date'];
  if (date == null) {
    return Response(400, body: jsonEncode({"message": "Date required"}));
  }

  return await withPoolConn((conn) async {

    // total employees
    final totalRes =
        await conn.query('SELECT COUNT(*) AS total FROM users');

    // present
    final presentRes = await conn.query(
      '''
      SELECT COUNT(DISTINCT user_id) AS presentToday
      FROM attendance
      WHERE DATE(in_time) = ?
      ''',
      [date],
    );

    // leave (approved)
    final leaveRes = await conn.query(
      '''
      SELECT COUNT(DISTINCT user_id) AS leaveToday
      FROM leave_requests
      WHERE status = 'Approved'
        AND from_date <= ?
        AND to_date >= ?
      ''',
      [date, date],
    );

    final totalEmployees =
        (totalRes.first['total'] as num).toInt();
    final presentToday =
        (presentRes.first['presentToday'] as num).toInt();
    final leaveToday =
        (leaveRes.first['leaveToday'] as num).toInt();

    final absentToday = totalEmployees - presentToday - leaveToday;

    print("DATE = $date");
    print("LEAVE = $leaveToday");

    return Response.ok(
      jsonEncode({
        "ok": true,
        "data": {
          "totalEmployees": totalEmployees,
          "presentToday": presentToday,
          "leaveToday": leaveToday,
          "absentToday": absentToday
        }
      }),
      headers: {"Content-Type": "application/json"},
    );
  });
}


    /// ================= ATTENDANCE LIST =================
    if (path == 'api/attendance/list' && method == 'GET') {
      final uid = await verifyToken(req);
      if (uid == null) {
        return Response(401,
            body: jsonEncode({"message": "Invalid token"}),
            headers: {"Content-Type": "application/json"});
      }

      return await withPoolConn((conn) async {
        final rows = await conn.query(
          'SELECT id, user_id, in_time, out_time, latitude, longitude, approval_status FROM attendance WHERE user_id=? ORDER BY id DESC',
          [uid]);

        final data = rows
            .map((r) => {
                  "id": r['id'],
                  "user_id": r['user_id'], 
                  "in_time": r['in_time']?.toString(),
                  "out_time": r['out_time']?.toString(),
                  "lat": r['latitude'],
                  "lng": r['longitude'],
                  "status": r['approval_status'], 
                })
            .toList();

        return Response.ok(jsonEncode({"ok": true, "data": data}),
            headers: {"Content-Type": "application/json"});
      });
    }

    /// ================= NOT FOUND =================
    return Response.notFound(
      jsonEncode({"message": "Route not found"}),
      headers: {"Content-Type": "application/json"},
    );
  });

  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final server = await io.serve(handler, '0.0.0.0', port);

  print('Server running at http://${server.address.host}:${server.port}');
}
