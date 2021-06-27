from pymongo import ASCENDING, CursorType
import time


def get_processor_status(db):
    if "process" not in db.list_collection_names():
        db.create_collection("process", capped=True, size=100000)
    oplog = db['process']
    try:
        first = oplog.find().sort('$natural', ASCENDING).limit(-1).next()
    except StopIteration:
        oplog.insert_one({'msg': 'Ready', 'step': 0})
        first = oplog.find().sort('$natural', ASCENDING).limit(-1).next()
    temp_id = first['_id']
    while True:
        cursor = oplog.find({'_id': {'$gt': temp_id}},
                            cursor_type=CursorType.TAILABLE_AWAIT,
                            oplog_replay=True)
        while cursor.alive:
            for doc in cursor:
                temp_id = doc['_id']
                print(doc)
            # We end up here if the find() returned no documents or if the
            # tailable cursor timed out (no new documents were added to the
            # collection for more than 1 second).
            time.sleep(1)
